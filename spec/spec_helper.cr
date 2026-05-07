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
    getter labels : Hash(String, String)

    def initialize(@name, @namespace, @labels = {} of String => String)
    end
  end

  struct MockTargetFunction
    getter name : String?
    getter match_labels : Hash(String, String)?
    getter match_expressions : Array(FunctionAccessRule::TargetFunction::MatchExpressions)?

    def initialize(@name, @match_labels = nil, @match_expressions = nil)
    end
  end

  struct MockSpec
    getter target_function : MockTargetFunction
    getter from : Array(MockFromPeer)?

    def initialize(@target_function, @from)
    end
  end

  def initialize(name : String, namespace : String, target_function : MockTargetFunction, from_peers : Array(MockFromPeer)?)
    @metadata = MockMetadata.new(name, namespace)
    @spec = MockSpec.new(target_function, from_peers)
  end
end

# Helper to create mock FunctionAccessRule resources for testing
# target_function can be a String (treated as name) or a MockTargetFunction
def create_mock_function_rule(name : String, namespace : String, target_function : String | MockFunctionAccessRule::MockTargetFunction, from_peers : Array(MockFromPeer))
  tf = case target_function
       in String
         MockFunctionAccessRule::MockTargetFunction.new(target_function)
       in MockFunctionAccessRule::MockTargetFunction
         target_function
       end
  MockFunctionAccessRule.new(name, namespace, tf, from_peers).as(Kubernetes::Resource(FunctionAccessRule))
end

# Extension to allow testing private methods and stubbing caches
class FissionAuthService
  # Expose private methods for testing
  def parse_path_pattern_for_test(pattern : String) : Array(Hash(String, String))
    parse_path_pattern(pattern)
  end

  def match_path_pattern_for_test(request_path : String, pattern : String) : {matched: Bool, params: Hash(String, String)}
    match_path_pattern(request_path, pattern)
  end
end
