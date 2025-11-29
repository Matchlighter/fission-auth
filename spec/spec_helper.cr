require "spec"
require "../src/fission_auth_service"

Spec.before_each do
  Log.setup(:none)
end

# Mock objects for testing
class MockIPBlock
  getter cidr : String
  getter except : Array(String)?

  def initialize(@cidr, @except)
  end
end

class MockPodSelector
  getter match_labels : Hash(String, String)?

  def initialize(@match_labels)
  end
end

class MockNamespaceSelector
  getter match_labels : Hash(String, JSON::Any)?

  def initialize(labels : Hash(String, String)?)
    @match_labels = labels ? labels.transform_values { |v| JSON::Any.new(v) } : nil
  end
end

class MockFromPeer
  getter ip_block : MockIPBlock?
  getter namespace_selector : MockNamespaceSelector?
  getter pod_selector : MockPodSelector?

  def initialize(@ip_block, @namespace_selector, @pod_selector)
  end
end

# Mock FunctionAccessRule for testing
class MockFunctionAccessRule
  getter metadata : MockMetadata
  getter spec : MockSpec

  struct MockMetadata
    getter name : String
    getter namespace : String

    def initialize(@name, @namespace)
    end
  end

  struct MockSpec
    getter target_function : String
    getter from : Array(MockFromPeer)?

    def initialize(@target_function, @from)
    end
  end

  def initialize(name : String, namespace : String, target_function : String, from_peers : Array(MockFromPeer)?)
    @metadata = MockMetadata.new(name, namespace)
    @spec = MockSpec.new(target_function, from_peers)
  end
end

# Helper to create mock FunctionAccessRule resources for testing
def create_mock_function_rule(name : String, namespace : String, target_function : String, from_peers : Array(MockFromPeer))
  MockFunctionAccessRule.new(name, namespace, target_function, from_peers).as(Kubernetes::Resource(FunctionAccessRule))
end

# Extension to allow stubbing cache for tests
class FissionAuthService
  def stub_rules_cache(namespace : String, rules : Array(Kubernetes::Resource(FunctionAccessRule)))
    @cache_mutex.synchronize do
      @rules_cache[namespace] = rules
    end
  end

  def stub_namespace_cache(cache : Hash(String, Hash(String, String)))
    @namespace_cache_mutex.synchronize do
      @namespace_cache = cache
    end
  end
end
