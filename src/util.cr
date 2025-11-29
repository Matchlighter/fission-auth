def cidr_matches?(ip : String, cidr : String) : Bool
  # Parse CIDR notation (e.g., "10.0.0.0/16")
  parts = cidr.split("/")
  parts << "32" if parts.size == 1

  network = parts[0]
  prefix_len = parts[1].to_i

  # Convert IPs to 32-bit integers
  ip_int = ip_to_int(ip)
  network_int = ip_to_int(network)

  return false if ip_int.nil? || network_int.nil?

  # Create subnet mask
  mask = (~0_u32) << (32 - prefix_len)

  # Check if IP is in the network
  (ip_int & mask) == (network_int & mask)
rescue
  false
end

def ip_to_int(ip : String) : UInt32?
  octets = ip.split(".")
  return nil if octets.size != 4

  result = 0_u32
  octets.each_with_index do |octet, i|
    val = octet.to_i?
    return nil if val.nil? || val < 0 || val > 255
    result |= val.to_u32 << (24 - i * 8)
  end

  result
rescue
  nil
end
