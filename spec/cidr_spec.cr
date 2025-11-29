require "./spec_helper"
require "../src/util"

describe "cidr_matches?" do
  it "matches IP exactly when no prefix specified" do
    cidr_matches?("192.168.1.1", "192.168.1.1").should be_true
    cidr_matches?("192.168.1.2", "192.168.1.1").should be_false
  end

  it "matches IP in /24 subnet" do
    cidr_matches?("10.0.1.1", "10.0.1.0/24").should be_true
    cidr_matches?("10.0.1.255", "10.0.1.0/24").should be_true
    cidr_matches?("10.0.1.128", "10.0.1.0/24").should be_true
    cidr_matches?("10.0.2.1", "10.0.1.0/24").should be_false
  end

  it "matches IP in /16 subnet" do
    cidr_matches?("10.0.1.1", "10.0.0.0/16").should be_true
    cidr_matches?("10.0.255.255", "10.0.0.0/16").should be_true
    cidr_matches?("10.1.0.0", "10.0.0.0/16").should be_false
  end

  it "matches IP in /8 subnet" do
    cidr_matches?("10.1.2.3", "10.0.0.0/8").should be_true
    cidr_matches?("10.255.255.255", "10.0.0.0/8").should be_true
    cidr_matches?("11.0.0.0", "10.0.0.0/8").should be_false
  end

  it "matches IP in /32 subnet (exact match)" do
    cidr_matches?("192.168.1.1", "192.168.1.1/32").should be_true
    cidr_matches?("192.168.1.2", "192.168.1.1/32").should be_false
  end

  it "matches IP in /0 subnet (all IPs)" do
    cidr_matches?("1.2.3.4", "0.0.0.0/0").should be_true
    cidr_matches?("255.255.255.255", "0.0.0.0/0").should be_true
  end

  it "handles odd prefix lengths" do
    cidr_matches?("192.168.1.1", "192.168.0.0/20").should be_true
    cidr_matches?("192.168.15.255", "192.168.0.0/20").should be_true
    cidr_matches?("192.168.16.0", "192.168.0.0/20").should be_false
  end

  it "returns false for invalid IPs" do
    cidr_matches?("not.an.ip.address", "10.0.0.0/8").should be_false
    cidr_matches?("256.1.1.1", "10.0.0.0/8").should be_false
    cidr_matches?("10.1.1", "10.0.0.0/8").should be_false
  end

  it "returns false for invalid CIDR" do
    cidr_matches?("10.1.1.1", "not.a.cidr/8").should be_false
    cidr_matches?("10.1.1.1", "10.0.0.0/invalid").should be_false
  end
end

describe "ip_to_int" do
  it "converts valid IP addresses to integers" do
    ip_to_int("0.0.0.0").should eq(0_u32)
    ip_to_int("255.255.255.255").should eq(0xFFFFFFFF_u32)
    ip_to_int("192.168.1.1").should eq(0xC0A80101_u32)
    ip_to_int("10.0.0.1").should eq(0x0A000001_u32)
  end

  it "returns nil for invalid IPs" do
    ip_to_int("not.an.ip").should be_nil
    ip_to_int("256.1.1.1").should be_nil
    ip_to_int("1.1.1").should be_nil
    ip_to_int("1.1.1.1.1").should be_nil
    ip_to_int("-1.0.0.0").should be_nil
  end
end
