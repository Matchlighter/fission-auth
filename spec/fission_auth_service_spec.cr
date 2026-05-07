require "./spec_helper"

describe FissionAuthService do
  describe "#matches_string_pattern?" do
    service = FissionAuthService.allocate

    it "matches exact function names" do
      service.matches_string_pattern?("my-function", "my-function").should be_true
      service.matches_string_pattern?("my-function", "other-function").should be_false
    end

    it "matches wildcard patterns with prefix" do
      service.matches_string_pattern?("auth-login", "auth-*").should be_true
      service.matches_string_pattern?("auth-logout", "auth-*").should be_true
      service.matches_string_pattern?("user-login", "auth-*").should be_false
    end

    it "matches catch-all wildcard" do
      service.matches_string_pattern?("any-function", "*").should be_true
      service.matches_string_pattern?("another-one", "*").should be_true
      service.matches_string_pattern?("", "*").should be_true
    end

    it "handles edge cases" do
      service.matches_string_pattern?("func", "func*").should be_true
      service.matches_string_pattern?("function", "func*").should be_true
    end

    it "matches regex patterns delimited by slashes" do
      service.matches_string_pattern?("auth-login", "/auth-.*/").should be_true
      service.matches_string_pattern?("user-login", "/auth-.*/").should be_false
      service.matches_string_pattern?("api-v2", "/api-v\\d+/").should be_true
      service.matches_string_pattern?("api-beta", "/api-v\\d+/").should be_false
    end

    it "treats single slash as exact match not regex" do
      service.matches_string_pattern?("/", "/").should be_true
      service.matches_string_pattern?("other", "/").should be_false
    end
  end

  describe "#parse_path_pattern" do
    service = FissionAuthService.allocate

    it "parses static path segments" do
      pattern = "/api/v1/users"
      segments = service.parse_path_pattern_for_test(pattern)
      segments.size.should eq(3)
      segments[0].should eq({"type" => "static", "value" => "api"})
      segments[1].should eq({"type" => "static", "value" => "v1"})
      segments[2].should eq({"type" => "static", "value" => "users"})
    end

    it "parses parameter segments without constraints" do
      pattern = "/api/{version}/users/{id}"
      segments = service.parse_path_pattern_for_test(pattern)
      segments.size.should eq(4)
      segments[0].should eq({"type" => "static", "value" => "api"})
      segments[1].should eq({"type" => "param", "name" => "version"})
      segments[2].should eq({"type" => "static", "value" => "users"})
      segments[3].should eq({"type" => "param", "name" => "id"})
    end

    it "parses parameter segments with regex constraints" do
      pattern = "/users/{id:\\d+}/posts/{slug:[a-z-]+}"
      segments = service.parse_path_pattern_for_test(pattern)
      segments.size.should eq(4)
      segments[1].should eq({"type" => "param", "name" => "id", "constraint" => "\\d+"})
      segments[3].should eq({"type" => "param", "name" => "slug", "constraint" => "[a-z-]+"})
    end

    it "handles root path" do
      pattern = "/"
      segments = service.parse_path_pattern_for_test(pattern)
      segments.size.should eq(0)
    end

    it "handles empty pattern" do
      pattern = ""
      segments = service.parse_path_pattern_for_test(pattern)
      segments.size.should eq(0)
    end

    it "ignores trailing slashes" do
      pattern = "/api/users/"
      segments = service.parse_path_pattern_for_test(pattern)
      segments.size.should eq(2)
    end
  end

  describe "#match_path_pattern" do
    service = FissionAuthService.allocate

    it "matches identical static paths" do
      result = service.match_path_pattern_for_test("/api/users", "/api/users")
      result[:matched].should be_true
      result[:params].size.should eq(0)
    end

    it "does not match different static paths" do
      result = service.match_path_pattern_for_test("/api/users", "/api/posts")
      result[:matched].should be_false
    end

    it "extracts parameters from simple paths" do
      result = service.match_path_pattern_for_test("/users/123", "/users/{id}")
      result[:matched].should be_true
      result[:params]["id"].should eq("123")
    end

    it "extracts multiple parameters" do
      result = service.match_path_pattern_for_test("/api/v2/users/john/posts/456", "/api/{version}/users/{username}/posts/{id}")
      result[:matched].should be_true
      result[:params]["version"].should eq("v2")
      result[:params]["username"].should eq("john")
      result[:params]["id"].should eq("456")
    end

    it "validates parameter constraints (numeric)" do
      result = service.match_path_pattern_for_test("/users/123", "/users/{id:\\d+}")
      result[:matched].should be_true
      result[:params]["id"].should eq("123")
    end

    it "rejects parameters that fail constraint validation" do
      result = service.match_path_pattern_for_test("/users/abc", "/users/{id:\\d+}")
      result[:matched].should be_false
    end

    it "validates parameter constraints (alphanumeric with hyphens)" do
      result = service.match_path_pattern_for_test("/posts/hello-world", "/posts/{slug:[a-z0-9-]+}")
      result[:matched].should be_true
      result[:params]["slug"].should eq("hello-world")
    end

    it "rejects when constraint pattern doesn't match" do
      result = service.match_path_pattern_for_test("/posts/HELLO", "/posts/{slug:[a-z]+}")
      result[:matched].should be_false
    end

    it "allows trailing segments in request" do
      result = service.match_path_pattern_for_test("/api/users/123/profile", "/api/users/{id}")
      result[:matched].should be_true
      result[:params]["id"].should eq("123")
    end

    it "fails when request has fewer segments than pattern" do
      result = service.match_path_pattern_for_test("/api/users", "/api/users/{id}")
      result[:matched].should be_false
    end

    it "handles empty request path" do
      result = service.match_path_pattern_for_test("/", "/api/users")
      result[:matched].should be_false
    end

    it "handles root pattern" do
      result = service.match_path_pattern_for_test("/anything", "/")
      result[:matched].should be_true
    end

    it "matches path with complex regex constraints" do
      result = service.match_path_pattern_for_test("/api/1.2/items", "/api/{version:[0-9.]+}/items")
      result[:matched].should be_true
      result[:params]["version"].should eq("1.2")
    end

    it "rejects path with invalid complex regex" do
      result = service.match_path_pattern_for_test("/api/invalid/items", "/api/{version:[0-9.]+}/items")
      result[:matched].should be_false
    end

    it "handles multiple parameter patterns in a single pattern" do
      result = service.match_path_pattern_for_test("/users/john/posts/42/comments/5", "/users/{user}/posts/{post}/comments/{comment}")
      result[:matched].should be_true
      result[:params]["user"].should eq("john")
      result[:params]["post"].should eq("42")
      result[:params]["comment"].should eq("5")
    end
  end

end
