require "json"
require "kubernetes"
require "uri"
require "netmask"

# Fission Forward Auth Microservice
# Validates incoming requests to FaaS functions based on CRD access rules
# Queries pod-watcher service to determine source pod information

# Import the CRD using Kubernetes client
Kubernetes.import_crd("k8s/crd-functionaccessrule.yaml")

class FissionAuthService
  @k8s : Kubernetes::Client
  @pod_watcher_url : String

  @cache_mutex = Mutex.new
  @rules_cache = Hash(String, Hash(String, FunctionAccessRule)).new

  @namespace_cache_mutex = Mutex.new
  @namespace_cache = Hash(String, Hash(String, String)).new

  def initialize
    @k8s = Kubernetes::Client.new
    @pod_watcher_url = ENV.fetch("POD_WATCHER_URL", "http://pod-watcher.pod-watcher.svc.cluster.local:8080")
    Log.info { "Initialized Fission Auth Service" }
    Log.info { "Pod Watcher URL: #{@pod_watcher_url}" }

    # Start watching for changes
    spawn_watch_namespaces
    spawn_watch_rules
  end

  def spawn_watch_namespaces
    spawn do
      Log.info { "Starting watch on Namespace resources..." }

      @k8s.watch_namespaces() do |watch|
        ns = watch.object

        @namespace_cache_mutex.synchronize do
          case watch
          when .added?, .modified?
            labels = ns.metadata.labels || {} of String => String
            @namespace_cache[ns.metadata.name] = labels
            Log.debug { "Updated namespace labels cache for #{ns.metadata.name}" }
          when .deleted?
            @namespace_cache.delete(ns.metadata.name)
            Log.debug { "Removed namespace from cache: #{ns.metadata.name}" }
          end
        end
      end
    end
  end

  def spawn_watch_rules
    spawn do
      Log.info { "Starting watch on FunctionAccessRule resources..." }

      # Watch all namespaces
      @k8s.watch_functionaccessrules() do |watch|
        rule = watch.object
        namespace = rule.metadata.namespace

        @cache_mutex.synchronize do
          @rules_cache[namespace] ||= {} of String => FunctionAccessRule

          case watch
          when .added?, .modified?
            @rules_cache[namespace][rule.metadata.name] = rule.spec
            Log.debug { "Updated FunctionAccessRule cache for #{namespace}/#{rule.metadata.name}" }
          when .deleted?
            @rules_cache[namespace].delete(rule.metadata.name)
            Log.debug { "Removed FunctionAccessRule from cache: #{namespace}/#{rule.metadata.name}" }
          end
        end
      end
    end
  end

  def get_rules_for_namespace(namespace : String) : Array(FunctionAccessRule)
    @cache_mutex.synchronize do
      @rules_cache[namespace].try(&.values) || [] of FunctionAccessRule
    end
  end

  def get_pod_metadata(ip : String) : JSON::Any?
    response = HTTP::Client.get("#{@pod_watcher_url}/pod?ip=#{ip}")

    if response.status_code == 200
      JSON.parse(response.body)
    else
      nil
    end
  rescue ex
    Log.error { "Error querying pod-watcher for IP #{ip}: #{ex.message}" }
    nil
  end

  def extract_function_info(path : String) : {namespace: String?, function: String?}
    # Path format: /namespace/function or /function
    parts = path.split("/").reject(&.empty?)
    parts.shift if parts[0] == ""

    if @namespace_cache.has_key?(parts[0])
      # First part is a namespace
      namespace = parts.shift
      return {namespace: namespace, function: parts.join("/")}
    end

    {namespace: "default", function: parts.join("/")}
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

  def matches_namespace_selector?(namespace : String, selector) : Bool
    # Get namespace labels from cache instead of making API call
    ns_labels = @namespace_cache_mutex.synchronize do
      @namespace_cache[namespace]?
    end

    return false unless ns_labels

    # Check name
    if name = selector.name
      return false unless namespace == name
    end

    # Check matchLabels
    if match_labels = selector.match_labels
      match_labels.each do |key, value|
        # Convert JSON::Any to String for comparison
        return false unless ns_labels[key]? == value
      end
    end

    # TODO: Implement matchExpressions if needed

    true
  rescue
    false
  end

  def matches_pod_selector?(pod_labels : Hash(String, String), selector) : Bool
    # Check matchLabels
    if match_labels = selector.match_labels
      match_labels.each do |key, value|
        return false unless pod_labels[key]? == value
      end
    end

    # TODO: Implement matchExpressions if needed

    true
  end

  def check_authorization(real_ip : String, request_path : String) : {allowed: Bool, reason: String, headers: Hash(String, String)}
    headers = {} of String => String

    # Extract function information from path
    func_info = extract_function_info(request_path)

    unless func_info[:function]
      return {allowed: false, reason: "Cannot determine target function", headers: headers}
    end

    target_namespace = func_info[:namespace].not_nil!
    function_uri = URI.parse(func_info[:function].not_nil!)

    Log.info { "Checking auth for function #{target_namespace}/#{function_uri.path} from IP #{real_ip}" }

    # Get pod metadata from pod-watcher
    pod_metadata = get_pod_metadata(real_ip)

    # Extract source pod information
    source_namespace = pod_metadata.try(&.["namespace"].as_s)
    source_pod = pod_metadata.try(&.["name"].as_s)

    Log.info { "Source: #{source_namespace}/#{source_pod}" }

    headers["X-Source-Namespace"] = source_namespace || ""
    headers["X-Source-Pod"] = source_pod || ""
    headers["X-Source-Type"] = pod_metadata ? "cluster" : "external"

    # Get access rules for the target namespace
    rules = get_rules_for_namespace(target_namespace)

    # Find matching rules
    matching_rules = rules.select do |rule|
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
          next unless pod_metadata

          unless matches_namespace_selector?(source_namespace.as(String), ns_selector)
            next
          end
        end

        # Check podSelector
        if pod_selector = peer.pod_selector
          next unless pod_metadata

          source_pod_labels = pod_metadata["labels"]?.try(&.as_h).as?(Hash(String, String)) || {} of String => String
          unless matches_pod_selector?(source_pod_labels, pod_selector)
            next
          end
        end

        # Check ipBlock
        if ip_block = peer.ip_block
          nm = Netmask.new(ip_block.not_nil!.cidr)
          unless nm.matches?(real_ip)
            next
          end
        end

        # If we got here, this peer matches
        return {allowed: true, reason: "Allowed by NetworkPolicy-style rule", headers: headers}
      end
    end

    # If we get here, no rule explicitly allowed it
    {allowed: false, reason: "Not explicitly allowed", headers: headers}
  end
end
