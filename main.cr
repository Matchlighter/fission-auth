require "http/server"
require "http/client"
require "log"

require "./src/fission_auth_service"

Log.setup(:info)

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
  when {"GET", "/authorize"}
    # Forward auth check
    real_ip = context.request.headers["X-Real-IP"]? ||
              context.request.headers["X-Forwarded-For"]?.try(&.split(",").first.strip) ||
              context.request.remote_address.try(&.to_s) || "unknown"

    request_path = context.request.headers["X-Forwarded-Uri"]? || context.request.path

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
