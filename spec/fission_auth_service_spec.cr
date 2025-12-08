require "./spec_helper"

describe FissionAuthService do
  describe "#matches_pattern?" do
    service = FissionAuthService.allocate

    it "matches exact function names" do
      service.matches_pattern?("my-function", "my-function").should be_true
      service.matches_pattern?("my-function", "other-function").should be_false
    end

    it "matches wildcard patterns with prefix" do
      service.matches_pattern?("auth-login", "auth-*").should be_true
      service.matches_pattern?("auth-logout", "auth-*").should be_true
      service.matches_pattern?("user-login", "auth-*").should be_false
    end

    it "matches wildcard patterns with suffix" do
      service.matches_pattern?("login-handler", "*-handler").should be_true
      service.matches_pattern?("logout-handler", "*-handler").should be_true
      service.matches_pattern?("login-service", "*-handler").should be_false
    end

    it "matches catch-all wildcard" do
      service.matches_pattern?("any-function", "*").should be_true
      service.matches_pattern?("another-one", "*").should be_true
      service.matches_pattern?("", "*").should be_true
    end

    it "handles edge cases" do
      service.matches_pattern?("func", "func*").should be_true
      service.matches_pattern?("func", "*func").should be_true
      service.matches_pattern?("function", "func*").should be_true
      service.matches_pattern?("myfunc", "*func").should be_true
    end
  end

  describe "#extract_function_info" do
    service = FissionAuthService.allocate

    it "extracts function from single-part path" do
      result = service.extract_function_info("/my-function")
      result[:namespace].should be_nil
      result[:function].should eq("my-function")
    end

    it "extracts namespace and function from two-part path" do
      result = service.extract_function_info("/production/my-function")
      result[:namespace].should eq("production")
      result[:function].should eq("my-function")
    end

    it "handles path with trailing slash" do
      result = service.extract_function_info("/production/my-function/")
      result[:namespace].should eq("production")
      result[:function].should eq("my-function")
    end

    it "handles empty path" do
      result = service.extract_function_info("")
      result[:namespace].should be_nil
      result[:function].should be_nil
    end

    it "handles root path" do
      result = service.extract_function_info("/")
      result[:namespace].should be_nil
      result[:function].should be_nil
    end

    it "handles path with multiple segments (uses first two)" do
      result = service.extract_function_info("/namespace/function/extra/path")
      result[:namespace].should eq("namespace")
      result[:function].should eq("function")
    end

    it "handles function names with special characters" do
      result = service.extract_function_info("/my-function-v2")
      result[:namespace].should be_nil
      result[:function].should eq("my-function-v2")
    end

    it "handles namespace and function with hyphens" do
      result = service.extract_function_info("/my-namespace/my-function-v2")
      result[:namespace].should eq("my-namespace")
      result[:function].should eq("my-function-v2")
    end
  end

  describe "#matches_pod_selector?" do
    service = FissionAuthService.allocate

    it "matches when all labels are present" do
      pod_labels = {
        "app"     => JSON::Any.new("backend"),
        "version" => JSON::Any.new("v1"),
      }
      selector = MockPodSelector.new({"app" => "backend", "version" => "v1"})
      service.matches_pod_selector?(pod_labels, selector).should be_true
    end

    it "fails when a label is missing" do
      pod_labels = {
        "app" => JSON::Any.new("backend"),
      }
      selector = MockPodSelector.new({"app" => "backend", "version" => "v1"})
      service.matches_pod_selector?(pod_labels, selector).should be_false
    end

    it "fails when label value doesn't match" do
      pod_labels = {
        "app"     => JSON::Any.new("backend"),
        "version" => JSON::Any.new("v2"),
      }
      selector = MockPodSelector.new({"app" => "backend", "version" => "v1"})
      service.matches_pod_selector?(pod_labels, selector).should be_false
    end

    it "matches with empty selector (matches all)" do
      pod_labels = {
        "app" => JSON::Any.new("backend"),
      }
      selector = MockPodSelector.new(nil)
      service.matches_pod_selector?(pod_labels, selector).should be_true
    end

    it "matches with subset of labels" do
      pod_labels = {
        "app"     => JSON::Any.new("backend"),
        "version" => JSON::Any.new("v1"),
        "tier"    => JSON::Any.new("production"),
      }
      selector = MockPodSelector.new({"app" => "backend"})
      service.matches_pod_selector?(pod_labels, selector).should be_true
    end

    it "handles integer values as JSON::Any" do
      pod_labels = {
        "app"      => JSON::Any.new("backend"),
        "replicas" => JSON::Any.new(3_i64),
      }
      selector = MockPodSelector.new({"app" => "backend"})
      service.matches_pod_selector?(pod_labels, selector).should be_true
    end
  end
end
