require "json"
require "kubernetes"

require "./util"

# Fission Forward Auth Microservice
# Validates incoming requests to FaaS functions based on CRD access rules
# Queries pod-watcher service to determine source pod information

# Import the CRD using Kubernetes client
Kubernetes.import_crd("k8s/crd-functionaccessrule.yaml")

class FissionAuthService
  @k8s : Kubernetes::Client
  @pod_watcher_url : String
  @rules_cache = Hash(String, Array(Kubernetes::Resource(FunctionAccessRule))).new
  @cache_mutex = Mutex.new
  @namespace_cache = Hash(String, Hash(String, String)).new
  @namespace_cache_mutex = Mutex.new

  def initialize
    @k8s = Kubernetes::Client.new
    @pod_watcher_url = ENV.fetch("POD_WATCHER_URL", "http://pod-watcher.pod-watcher.svc.cluster.local:8080")
    Log.info { "Initialized Fission Auth Service" }
    Log.info { "Pod Watcher URL: #{@pod_watcher_url}" }

    # Do initial load of all rules and namespaces
    load_all_rules
    load_namespace_labels

    # Start watching for changes
    spawn_watch_rules
    spawn_watch_namespaces
  end

  def load_all_rules
    Log.info { "Loading all access rules..." }

    # Get all namespaces and fetch rules from each
    @cache_mutex.synchronize do
      @rules_cache.clear

      rules = @k8s.functionaccessrules(namespace: nil)
      rules.each do |rule|
        ns = rule.metadata.namespace
        @rules_cache[ns] ||= [] of Kubernetes::Resource(FunctionAccessRule)
        @rules_cache[ns] << rule
      end
    end

    Log.info { "Loaded rules from #{@rules_cache.size} namespaces" }
  end

  def load_namespace_labels
    Log.info { "Loading namespace labels..." }

    @namespace_cache_mutex.synchronize do
      @namespace_cache.clear
      @k8s.namespaces.each do |ns|
        labels = ns.metadata.labels || {} of String => String
        @namespace_cache[ns.metadata.name] = labels
      end
    end

    Log.info { "Loaded labels for #{@namespace_cache.size} namespaces" }
  end

  def spawn_watch_namespaces
    spawn do
      loop do
        begin
          Log.debug { "Starting watch on Namespace resources..." }

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

          Log.warn { "Namespace watch connection closed, reconnecting in 5 seconds..." }
          sleep 5.seconds
        rescue ex
          Log.error { "Error in namespace watch loop: #{ex.message}" }
          sleep 5.seconds
        end
      end
    end
  end

  def spawn_watch_rules
    spawn do
      loop do
        begin
          Log.info { "Starting watch on FunctionAccessRule resources..." }

          # Watch all namespaces
          @k8s.watch_functionaccessrules() do |watch|
            rule = watch.object
            namespace = rule.metadata.namespace

            @cache_mutex.synchronize do
              case watch
              when .added?, .modified?
                # Reload all rules for this namespace to keep cache consistent
                begin
                  rules = @k8s.functionaccessrules(namespace: namespace)
                  if rules.size > 0
                    @rules_cache[namespace] = rules.to_a
                  else
                    @rules_cache.delete(namespace)
                  end
                rescue ex
                  Log.error { "Error reloading rules for namespace #{namespace}: #{ex.message}" }
                end
              when .deleted?
                # Reload all rules for this namespace
                begin
                  rules = @k8s.functionaccessrules(namespace: namespace)
                  if rules.size > 0
                    @rules_cache[namespace] = rules.to_a
                  else
                    @rules_cache.delete(namespace)
                  end
                rescue ex
                  Log.error { "Error reloading rules for namespace #{namespace}: #{ex.message}" }
                end
              end
            end
          end

          Log.warn { "Watch connection closed, reconnecting in 5 seconds..." }
          sleep 5.seconds
        rescue ex
          Log.error { "Error in watch loop: #{ex.message}" }
          Log.error { ex.backtrace.join("\n") }
          sleep 5.seconds
        end
      end
    end
  end

  def get_rules_for_namespace(namespace : String) : Array(Kubernetes::Resource(FunctionAccessRule))
    @cache_mutex.synchronize do
      @rules_cache[namespace]? || [] of Kubernetes::Resource(FunctionAccessRule)
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

    case parts.size
    when 0
      {namespace: nil, function: nil}
    when 1
      {namespace: nil, function: parts[0]}
    else
      {namespace: parts[0], function: parts[1]}
    end
  end

  def matches_pattern?(function : String, pattern : String) : Bool
    if pattern == "*"
      true
    elsif pattern.ends_with?("*")
      prefix = pattern[0..-2]
      function.starts_with?(prefix)
    elsif pattern.starts_with?("*")
      suffix = pattern[1..]
      function.ends_with?(suffix)
    else
      function == pattern
    end
  end

  def matches_ip_block?(ip : String, ip_block) : Bool
    # Parse CIDR and check if IP is in range
    cidr = ip_block.cidr

    return false unless cidr_matches?(ip, cidr)

    # Check except list
    if except_list = ip_block.except
      except_list.each do |except_cidr|
        return false if cidr_matches?(ip, except_cidr)
      end
    end

    true
  rescue
    false
  end

  def matches_namespace_selector?(namespace : String, selector) : Bool
    # Get namespace labels from cache instead of making API call
    ns_labels = @namespace_cache_mutex.synchronize do
      @namespace_cache[namespace]?
    end

    return false unless ns_labels

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

    target_function = func_info[:function].not_nil!
    target_namespace = func_info[:namespace] || "default"

    Log.info { "Checking auth for function #{target_namespace}/#{target_function} from IP #{real_ip}" }

    # Get pod metadata from pod-watcher
    pod_metadata = get_pod_metadata(real_ip)

    if pod_metadata.nil?
      # Not a pod in the cluster - could be external
      Log.info { "No pod found for IP #{real_ip} - treating as external" }
      headers["X-Source-Type"] = "external"

      # Check if any rule allows external access via ipBlock
      rules = get_rules_for_namespace(target_namespace)

      matching_rule = rules.find do |rule|
        next false unless matches_pattern?(target_function, rule.spec.target_function)
        next false unless rule.spec.from

        rule.spec.from.not_nil!.any? do |peer|
          peer.ip_block && matches_ip_block?(real_ip, peer.ip_block.not_nil!)
        end
      end

      if matching_rule
        return {allowed: true, reason: "External access allowed by ipBlock rule", headers: headers}
      else
        return {allowed: false, reason: "External access denied", headers: headers}
      end
    end

    # Extract source pod information
    source_namespace = pod_metadata["namespace"].as_s
    source_pod = pod_metadata["name"].as_s
    source_labels = pod_metadata["labels"]?.try(&.as_h).as?(Hash(String, String)) || {} of String => String

    Log.info { "Source: #{source_namespace}/#{source_pod}" }

    headers["X-Source-Namespace"] = source_namespace
    headers["X-Source-Pod"] = source_pod
    headers["X-Source-Type"] = "cluster"

    # Get access rules for the target namespace
    rules = get_rules_for_namespace(target_namespace)

    if rules.empty?
      Log.info { "No access rules defined for namespace #{target_namespace}" }
      # Default policy: allow same-namespace
      if source_namespace == target_namespace
        return {allowed: true, reason: "Same namespace (no rules defined)", headers: headers}
      else
        return {allowed: false, reason: "Cross-namespace denied (no rules defined)", headers: headers}
      end
    end

    # Find matching rules
    matching_rules = rules.select do |rule|
      matches_pattern?(target_function, rule.spec.target_function)
    end

    if matching_rules.empty?
      Log.info { "No rules match function #{target_function}" }
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
      from_peers = rule.spec.from
      next unless from_peers

      # Check if any peer in the from list matches
      from_peers.each do |peer|
        # Check namespaceSelector
        if ns_selector = peer.namespace_selector
          unless matches_namespace_selector?(source_namespace, ns_selector)
            next
          end
        end

        # Check podSelector
        if pod_selector = peer.pod_selector
          unless matches_pod_selector?(source_labels, pod_selector)
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
