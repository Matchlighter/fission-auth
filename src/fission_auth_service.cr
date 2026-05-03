require "json"
require "kubernetes"
require "uri"
require "netmask"

# Fission Forward Auth Microservice
# Validates incoming requests to FaaS functions based on CRD access rules
# Queries pod-watcher service to determine source pod information

# Import the CRDs using Kubernetes client
Kubernetes.import_crd("k8s/crd-functionaccessrule.yaml")

class FissionAuthService
  @k8s : Kubernetes::Client
  @pod_watcher_url : String

  @namespace_store : Kubernetes::SyncedStore(Kubernetes::Namespace)
  @rules_store : Kubernetes::SyncedStore(Kubernetes::Resource(FunctionAccessRule))
  @trigger_store : Kubernetes::SyncedStore(Kubernetes::Resource(JSON::Any))

  def initialize
    @k8s = Kubernetes::Client.new
    @pod_watcher_url = ENV.fetch("POD_WATCHER_URL", "http://pod-watcher.pod-watcher.svc.cluster.local:8080")
    Log.info { "Initialized Fission Auth Service" }
    Log.info { "Pod Watcher URL: #{@pod_watcher_url}" }

    @namespace_store = @k8s.create_synced_store(Kubernetes::Namespace, "api/v1/namespaces")
    @rules_store = @k8s.create_synced_store(Kubernetes::Resource(FunctionAccessRule), "apis/fission.io/v1/functionaccessrules")
    @trigger_store = @k8s.create_synced_store(Kubernetes::Resource(JSON::Any), "apis/fission.io/v1/httptriggers")
  end

  def get_pod_metadata(ip : String) : Kubernetes::Pod::Metadata?
    response = HTTP::Client.get("#{@pod_watcher_url}/pod?ip=#{ip}")

    if response.status_code == 200
      Kubernetes::Pod::Metadata.from_json(response.body_io)
    else
      nil
    end
  rescue ex
    Log.error { "Error querying pod-watcher for IP #{ip}: #{ex.message}" }
    nil
  end

  # Parse a Fission path pattern into segments, identifying parameters
  # e.g., "/api/{version}/users/{id}" becomes:
  # [{type: :static, value: "api"}, {type: :param, name: "version"}, {type: :static, value: "users"}, {type: :param, name: "id"}]
  private def parse_path_pattern(pattern : String) : Array(Hash(String, String))
    segments = [] of Hash(String, String)
    pattern.split("/").each do |segment|
      next if segment.empty?

      if segment.starts_with?("{") && segment.ends_with?("}")
        # Parameter: extract name and optional regex constraint
        inner = segment[1..-2]
        if inner.includes?(":")
          name, constraint = inner.split(":", 2)
          segments << {"type" => "param", "name" => name, "constraint" => constraint}
        else
          segments << {"type" => "param", "name" => inner}
        end
      else
        segments << {"type" => "static", "value" => segment}
      end
    end
    segments
  end

  # Match a request path against a pattern, extracting parameters
  # Returns {matched: bool, params: Hash(String, String)}
  private def match_path_pattern(request_path : String, pattern : String) : {matched: Bool, params: Hash(String, String)}
    pattern_segments = parse_path_pattern(pattern)
    request_segments = request_path.split("/").reject(&.empty?)

    params = {} of String => String
    pattern_idx = 0
    request_idx = 0

    while pattern_idx < pattern_segments.size && request_idx < request_segments.size
      pattern_seg = pattern_segments[pattern_idx]
      request_seg = request_segments[request_idx]

      if pattern_seg["type"] == "static"
        # Static segment must match exactly
        return {matched: false, params: params} unless pattern_seg["value"] == request_seg
        pattern_idx += 1
        request_idx += 1
      elsif pattern_seg["type"] == "param"
        # Parameter segment matches if it satisfies constraint
        if constraint = pattern_seg["constraint"]?
          # Validate against regex constraint
          regex = Regex.new("^#{constraint}$")
          return {matched: false, params: params} unless regex.match(request_seg)
        end
        # Capture the parameter
        params[pattern_seg["name"]] = request_seg
        pattern_idx += 1
        request_idx += 1
      end
    end

    # Check if we've consumed all pattern segments
    if pattern_idx == pattern_segments.size
      # Pattern fully matched
      # If request has more segments, it's still valid (trailing path allowed)
      return {matched: true, params: params}
    else
      # Pattern not fully matched
      {matched: false, params: params}
    end
  end

  def resolve_url_to_function(request_path : String) : {namespace: String?, function: String?, params: Hash(String, String)}
    # Query all HTTPTriggers to find a matching route
    all_triggers = @trigger_store.all

    matching_trigger = all_triggers.each do |trigger|
      spec = trigger.spec
      next unless spec.is_a?(JSON::Any)

      # Check relativeurl or path from ingressconfig
      relative_url = spec["relativeurl"]?.try(&.as_s) || ""
      ingress_path = spec["ingressconfig"]?.try { |ic| ic["path"]?.try(&.as_s) } || ""

      # Try to match against relativeurl first, then ingress path
      path_to_match = relative_url.empty? ? ingress_path : relative_url
      next if path_to_match.empty?

      # Match with full Fission URL parameter support
      match_result = match_path_pattern(request_path, path_to_match)

      if match_result[:matched]
        function_ref = trigger.spec["functionref"]
        function_name = function_ref["name"]?.try(&.as_s) || ""

        return {namespace: trigger.metadata.namespace, function: function_name, params: match_result[:params]}
      end
    end

    # Fallback: if no HTTPTrigger found, return nil to indicate resolution failed
    {namespace: nil, function: nil, params: {} of String => String}
  end

  def extract_function_info(path : String) : {namespace: String?, function: String?, params: Hash(String, String)}?
    # Path format: /namespace/function or /function
    # First, try to resolve using HTTPTriggers (the proper way)
    resolved = resolve_url_to_function(path)

    if resolved[:function]
      Log.info { "Resolved function via HTTPTrigger: #{resolved[:namespace]}/#{resolved[:function]}" }
      if resolved[:params].size > 0
        Log.info { "Extracted URL parameters: #{resolved[:params]}" }
      end
      return resolved
    end

    # Fallback: parse path segments (legacy behavior)
    # This is kept for compatibility but HTTPTrigger resolution is preferred
    parts = path.split("/").reject(&.empty?)
    parts.shift if parts[0] == ""

    # if @namespace_store[parts[0]]
    #   # First part is a namespace
    #   namespace = parts.shift
    #   return {namespace: namespace, function: parts.join("/"), params: {} of String => String}
    # end

    # {namespace: "default", function: parts.join("/"), params: {} of String => String}

    nil
  end

  def matches_pattern?(function : String, pattern : String) : Bool
    function = function + "/" unless function.ends_with?("/")

    if pattern == "*"
      true
    elsif pattern.ends_with?("*")
      prefix = pattern[0..-2]
      function.starts_with?(prefix)
    else
      function == pattern || function == (pattern + "/")
    end
  end

  def matches_selector?(meta, selector) : Bool
    # Check name
    if selector.responds_to?(:name) && (match_name = selector.name)
      return false unless match_name == meta.name
    end

    # Check matchLabels
    if match_labels = selector.match_labels
      obj_labels = meta.labels
      match_labels.each do |key, value|
        # Convert JSON::Any to String for comparison
        return false unless obj_labels[key]? == value
      end
    end

    # TODO: Implement matchExpressions

    true
  rescue
    false
  end

  def check_authorization(real_ip : String, request_path : String) : {allowed: Bool, reason: String, headers: Hash(String, String)}
    headers = {} of String => String

    # Extract function information from path
    func_info = extract_function_info(request_path)

    if func_info.nil? || !func_info[:function]
      return {allowed: false, reason: "Cannot determine target function", headers: headers}
    end

    function_uri = URI.parse(func_info[:function].not_nil!)
    target_namespace = @namespace_store[func_info[:namespace].not_nil!]

    Log.info { "Checking auth for function #{target_namespace.metadata.name}:#{function_uri.path} from IP #{real_ip}" }

    # Get source pod metadata
    pod_metadata = get_pod_metadata(real_ip)
    source_namespace = pod_metadata ? @namespace_store[pod_metadata.namespace] : nil

    Log.info { "Source: #{pod_metadata.try(&.namespace)}/#{pod_metadata.try(&.name)}" }

    headers["X-Source-Namespace"] = pod_metadata.try(&.namespace) || ""
    headers["X-Source-Pod"] = pod_metadata.try(&.name) || ""
    headers["X-Source-Type"] = pod_metadata ? "cluster" : "external"

    # Find matching rules
    namespace_rules = @rules_store.all_for(target_namespace).map(&.spec)
    matching_rules = namespace_rules.select do |rule|
      matches_pattern?(function_uri.path, rule.target_function)
    end

    if matching_rules.empty?
      Log.info { "No rules match function #{function_uri.path}" }
      # No explicit rule - default deny for cross-namespace
      if source_namespace == target_namespace
        return {allowed: true, reason: "Same namespace (no matching rule)", headers: headers}
      else
        return {allowed: false, reason: "No matching access rule", headers: headers}
      end
    end

    # Evaluate rules with from field
    matching_rules.each do |rule|
      # If no from field, deny (explicit rules required)
      from_peers = rule.from
      next unless from_peers

      # Check if any peer in the from list matches
      from_peers.each do |peer|
        # Check namespaceSelector
        if ns_selector = peer.namespace_selector
          next unless source_namespace
          next unless matches_selector?(source_namespace.metadata, ns_selector)
        end

        # Check podSelector
        if pod_selector = peer.pod_selector
          next unless pod_metadata
          next unless matches_selector?(pod_metadata, pod_selector)
        end

        # Check ipBlock
        if ip_block = peer.ip_block
          nm = Netmask.new(ip_block.not_nil!.cidr)
          next unless nm.matches?(real_ip)
        end

        # If we got here, this peer matches
        return {allowed: true, reason: "Allowed by NetworkPolicy-style rule", headers: headers}
      end
    end

    # If we get here, no rule explicitly allowed it
    {allowed: false, reason: "Not explicitly allowed", headers: headers}
  end
end
