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

  @namespace_store : Kubernetes::SyncedStore(Kubernetes::Namespace)
  @rules_store : Kubernetes::SyncedStore(Kubernetes::Resource(FunctionAccessRule))

  def initialize
    @k8s = Kubernetes::Client.new
    @pod_watcher_url = ENV.fetch("POD_WATCHER_URL", "http://pod-watcher.pod-watcher.svc.cluster.local:8080")
    Log.info { "Initialized Fission Auth Service" }
    Log.info { "Pod Watcher URL: #{@pod_watcher_url}" }

    @namespace_store = @k8s.create_synced_store(Kubernetes::Namespace, "api/v1/namespaces")
    @rules_store = @k8s.create_synced_store(Kubernetes::Resource(FunctionAccessRule), "apis/fission.io/v1/functionaccessrules")
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

  def extract_function_info(path : String) : {namespace: String?, function: String?}
    # Path format: /namespace/function or /function
    parts = path.split("/").reject(&.empty?)
    parts.shift if parts[0] == ""

    if @namespace_store[parts[0]]
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

    unless func_info[:function]
      return {allowed: false, reason: "Cannot determine target function", headers: headers}
    end

    function_uri = URI.parse(func_info[:function].not_nil!)
    target_namespace = @namespace_store[func_info[:namespace].not_nil!]

    Log.info { "Checking auth for function #{target_namespace}/#{function_uri.path} from IP #{real_ip}" }

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
