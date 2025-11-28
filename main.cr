require "http/server"
require "http/client"
require "json"
require "log"
require "kubernetes"

# Fission Forward Auth Microservice
# Validates incoming requests to FaaS functions based on CRD access rules
# Queries pod-watcher service to determine source pod information

Log.setup(:info)

# Import the CRD using Kubernetes client
Kubernetes.import_crd("k8s/crd-functionaccessrule.yaml")

class FissionAuthService
  @k8s : Kubernetes::Client
  @pod_watcher_url : String
  @rules_cache = Hash(String, Array(Kubernetes::Resource(FunctionAccessRule))).new
  @cache_mutex = Mutex.new

  def initialize
    @k8s = Kubernetes::Client.new
    @pod_watcher_url = ENV.fetch("POD_WATCHER_URL", "http://pod-watcher.pod-watcher.svc.cluster.local:8080")
    Log.info { "Initialized Fission Auth Service" }
    Log.info { "Pod Watcher URL: #{@pod_watcher_url}" }

    # Do initial load of all rules
    load_all_rules

    # Start watching for rule changes
    spawn_watch_rules
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

      # Check if any rule allows external access
      rules = get_rules_for_namespace(target_namespace)

      matching_rule = rules.find do |rule|
        matches_pattern?(target_function, rule.spec.target_function)
      end

      if matching_rule && matching_rule.spec.allow_external
        return {allowed: true, reason: "External access allowed by rule", headers: headers}
      else
        return {allowed: false, reason: "External access denied", headers: headers}
      end
    end

    # Extract source pod information
    source_namespace = pod_metadata["namespace"].as_s
    source_pod = pod_metadata["name"].as_s
    source_labels = pod_metadata["labels"]?.try(&.as_h) || {} of String => JSON::Any

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

    # Evaluate rules
    matching_rules.each do |rule|
      # Check deny list first
      if deny_ns = rule.spec.deny_namespaces
        if deny_ns.includes?(source_namespace)
          return {allowed: false, reason: "Namespace explicitly denied", headers: headers}
        end
      end

      # Check required labels
      if required_labels = rule.spec.require_pod_labels
        required_labels.each do |key, value|
          source_label_value = source_labels[key]?.try(&.as_s)
          unless source_label_value == value
            return {allowed: false, reason: "Required label #{key}=#{value} not present", headers: headers}
          end
        end
      end

      # Check allowed namespaces
      if allowed_ns = rule.spec.allowed_namespaces
        if allowed_ns.includes?(source_namespace)
          return {allowed: true, reason: "Namespace allowed by rule", headers: headers}
        end
      end
    end

    # If we get here, no rule explicitly allowed it
    {allowed: false, reason: "Not explicitly allowed", headers: headers}
  end
end

# Create auth service instance
auth_service = FissionAuthService.new

# HTTP Server
port = ENV.fetch("PORT", "8080").to_i
host = ENV.fetch("HOST", "0.0.0.0")

server = HTTP::Server.new do |context|
  case {context.request.method, context.request.path}
  when {"GET", "/health"}
    context.response.content_type = "application/json"
    context.response.status_code = 200
    context.response.print({"status" => "healthy"}.to_json)
  when {"GET", "/ready"}
    context.response.content_type = "application/json"
    context.response.status_code = 200
    context.response.print({"status" => "ready"}.to_json)
  else
    # Forward auth check
    real_ip = context.request.headers["X-Real-IP"]? ||
              context.request.headers["X-Forwarded-For"]?.try(&.split(",").first.strip) ||
              context.request.remote_address.try(&.to_s) || "unknown"

    request_path = context.request.headers["X-Original-URI"]? || context.request.path

    Log.info { "Auth check: #{context.request.method} #{request_path} from #{real_ip}" }

    result = auth_service.check_authorization(real_ip, request_path)

    if result[:allowed]
      context.response.status_code = 200
      result[:headers].each do |key, value|
        context.response.headers[key] = value
      end
      context.response.print("Authorized: #{result[:reason]}")
      Log.info { "✓ Authorized: #{result[:reason]}" }
    else
      context.response.status_code = 403
      result[:headers].each do |key, value|
        context.response.headers[key] = value
      end
      context.response.print("Forbidden: #{result[:reason]}")
      Log.info { "✗ Forbidden: #{result[:reason]}" }
    end
  end
end

address = server.bind_tcp host, port
Log.info { "Fission Auth Service starting on #{address}" }
server.listen
