require "json"
require "kubernetes"
require "uri"
require "netmask"

require "./multibimap"

# Fission Forward Auth Microservice
# Validates incoming requests to FaaS functions based on CRD access rules
# Queries pod-watcher service to determine source pod information

# Import the CRDs using Kubernetes client
Kubernetes.import_crd("k8s/crd-functionaccessrule.yaml")

def resource_uid(resource) : String
  "#{resource.metadata.namespace}/#{resource.metadata.name}"
end

class FissionAuthService
  alias FunctionResource = Kubernetes::Resource(JSON::Any)
  alias RuleResource = Kubernetes::Resource(FunctionAccessRule)

  @k8s : Kubernetes::Client
  @pod_watcher_url : String

  @namespace_store : Kubernetes::SyncedStore(Kubernetes::Namespace)
  @rules_store : Kubernetes::SyncedStore(RuleResource)
  @trigger_store : Kubernetes::SyncedStore(Kubernetes::Resource(JSON::Any))
  @function_store : Kubernetes::SyncedStore(Kubernetes::Resource(JSON::Any))

  @index_mutex : Mutex
  @fn_rule_map : MultiBiMap(String, String) # MultiBiMap(Function.uid, Rule.uid)

  def initialize
    @k8s = Kubernetes::Client.new
    @pod_watcher_url = ENV.fetch("POD_WATCHER_URL", "http://pod-watcher.pod-watcher.svc.cluster.local:8080")
    Log.info { "Initialized Fission Auth Service" }
    Log.info { "Pod Watcher URL: #{@pod_watcher_url}" }

    @index_mutex = Mutex.new
    @fn_rule_map = MultiBiMap(String, String).new

    @namespace_store = @k8s.create_synced_store(Kubernetes::Namespace, "api/v1/namespaces")
    @rules_store = @k8s.create_synced_store(RuleResource, "apis/fission.io/v1/functionaccessrules")
    @trigger_store = @k8s.create_synced_store(Kubernetes::Resource(JSON::Any), "apis/fission.io/v1/httptriggers")
    # TODO Only need to track Function metadata
    @function_store = @k8s.create_synced_store(FunctionResource, "apis/fission.io/v1/functions")

    @rules_store.on_change do |watch|
      @index_mutex.synchronize do
        resource = watch.object
        rule_uid = resource_uid(resource)

        @fn_rule_map.delete_right(rule_uid)

        if watch.added? || watch.modified?
          @function_store.all_for(resource.metadata.namespace).each do |func|
            if selector_matches?(resource.spec.target_function, func.metadata)
              @fn_rule_map.add(resource_uid(func), rule_uid)
            end
          end
        end
      end
    end

    @function_store.on_change do |watch|
      @index_mutex.synchronize do
        resource = watch.object
        func_uid = resource_uid(resource)

        @fn_rule_map.delete_left(func_uid)

        if watch.added? || watch.modified?
          @rules_store.all_for(resource.metadata.namespace).each do |rule|
            if selector_matches?(rule.spec.target_function, resource.metadata)
              @fn_rule_map.add(func_uid, resource_uid(rule))
            end
          end
        end
      end
    end
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

  def resolve_url_to_function(request_path : String) : FunctionResource?
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
        return @function_store["#{trigger.metadata.namespace.not_nil!}/#{function_name}"]
      end
    end

    # Fallback: if no HTTPTrigger found, return nil to indicate resolution failed
    nil
  end

  def matches_string_pattern?(name : String, pattern : String) : Bool
    if pattern == "*"
      true
    elsif pattern.starts_with?("/") && pattern.ends_with?("/") && pattern.size > 1
      !!Regex.new(pattern[1..-2]).match(name)
    elsif pattern.ends_with?("*")
      name.starts_with?(pattern[0..-2])
    else
      name == pattern
    end
  end

  def selector_matches?(selector, resource_meta)
    name = resource_meta.name
    labels = resource_meta.labels || {} of String => String

    if selector.responds_to?(:name) && (filt_name = selector.name)
      return false unless matches_string_pattern?(name, filt_name)
    end

    if match_labels = selector.match_labels
      match_labels.each do |key, value|
        return false unless labels[key]? == value
      end
    end

    if match_expressions = selector.match_expressions
      match_expressions.each do |expr|
        label_value = labels[expr.key]?
        case expr.operator
        when "In"           then return false unless label_value && expr.values.includes?(label_value)
        when "NotIn"        then return false if label_value && expr.values.includes?(label_value)
        when "Exists"       then return false unless label_value
        when "DoesNotExist" then return false if label_value
        end
      end
    end
    
    true
  end

  def check_authorization(real_ip : String, request_path : String) : {allowed: Bool, reason: String, headers: Hash(String, String)}
    headers = {} of String => String

    # Extract function information from path
    function = resolve_url_to_function(request_path)

    if function.nil?
      return {allowed: false, reason: "Cannot determine target function", headers: headers}
    end

    function_name = function.metadata.name
    target_namespace = @namespace_store[function.metadata.namespace.not_nil!].not_nil!

    Log.info { "Checking auth for function #{target_namespace.metadata.name}:#{function_name} from IP #{real_ip}" }

    # Get source pod metadata
    pod_metadata = get_pod_metadata(real_ip)
    source_namespace = pod_metadata ? @namespace_store[pod_metadata.namespace] : nil

    Log.info { "Source: #{pod_metadata.try(&.namespace)}/#{pod_metadata.try(&.name)}" }

    headers["X-Source-Namespace"] = pod_metadata.try(&.namespace) || ""
    headers["X-Source-Pod"] = pod_metadata.try(&.name) || ""
    headers["X-Source-Type"] = pod_metadata ? "cluster" : "external"

    # Find matching rules via pre-built index
    matching_rules = @index_mutex.synchronize do
      rule_ids = @fn_rule_map.for_left(resource_uid(function))
      rule_ids.map { |rid| @rules_store[rid] }.compact.map(&.spec).compact
    end

    if matching_rules.empty?
      Log.info { "No rules match function #{function_name}" }
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
          next unless selector_matches?(ns_selector, source_namespace.metadata)
        end

        # Check podSelector
        if pod_selector = peer.pod_selector
          next unless pod_metadata
          next unless selector_matches?(pod_selector, pod_metadata)
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
