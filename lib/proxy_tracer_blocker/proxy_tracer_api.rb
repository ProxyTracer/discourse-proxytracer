# frozen_string_literal: true

require "net/http"
require "json"
require "uri"
require "ipaddr"
require "securerandom"
require "cgi"
require "digest"

module ProxyTracerBlocker
  class ProxyTracerApi
    API_ENDPOINT = "https://api.proxytracer.com/v1/check/".freeze
    TOKEN_REGEX = /\A[0-9a-f]{48}\z/.freeze
    CHALLENGE_REGEX = /\A[0-9a-f]{48}\z/.freeze
    CLEARANCE_REGEX = /\A[0-9a-f]{48}\z/.freeze
    VALID_SCOPES = %w[visitor auth login signup email_login forgot_password].freeze

    CIRCUIT_BREAKER_THRESHOLD = 50
    CIRCUIT_BREAKER_TTL = 60

    WHITELIST_MUTEX = Mutex.new
    @cached_whitelist_raw = nil
    @cached_whitelist_parsed = []

    def self.clearance_key(token)
      return nil unless token.to_s.match?(TOKEN_REGEX)
      "proxytracer:clearance:#{Digest::SHA256.hexdigest(token)}"
    end

    def self.extract_client_ip(request)
      # Check reverse proxy headers only if they represent valid public IP addresses
      header_candidates = [
        request.env["HTTP_CF_CONNECTING_IP"].to_s.presence,
        request.env["HTTP_X_REAL_IP"].to_s.presence,
        request.env["HTTP_X_FORWARDED_FOR"]&.split(",")&.first&.strip.presence
      ].compact

      valid_header_ip = header_candidates.find do |candidate|
        ip = parse_and_validate_ip(candidate)
        ip && is_public_ip_addr?(ip)
      end

      fallback_remote = begin
        request.remote_ip.to_s.presence
      rescue StandardError
        nil
      end || request.env["REMOTE_ADDR"].to_s.presence

      raw_ip = valid_header_ip || fallback_remote
      return nil if raw_ip.blank?

      parsed = parse_and_validate_ip(raw_ip)
      parsed ? parsed.to_s : nil
    end

    def self.parse_and_validate_ip(raw_ip_str)
      return nil if raw_ip_str.blank?
      str = raw_ip_str.to_s.strip
      return nil if str.bytesize > 128 || str.include?("/") || str.match?(/[[:cntrl:]\s]/)

      begin
        parsed = IPAddr.new(str)
        if parsed.ipv6? && parsed.respond_to?(:ipv4_mapped?) && parsed.ipv4_mapped? && parsed.respond_to?(:native)
          parsed.native
        else
          parsed
        end
      rescue IPAddr::InvalidAddressError, StandardError
        nil
      end
    end

    def self.is_public_ip_addr?(parsed_ip)
      return false unless parsed_ip.is_a?(IPAddr)
      return false if parsed_ip.loopback?
      return false if parsed_ip.respond_to?(:private?) && parsed_ip.private?
      return false if parsed_ip.respond_to?(:link_local?) && parsed_ip.link_local?
      true
    end

    def self.parsed_whitelisted_ips
      current_raw = SiteSetting.Whitelisted_IPs.to_s
      return @cached_whitelist_parsed if @cached_whitelist_raw == current_raw

      WHITELIST_MUTEX.synchronize do
        return @cached_whitelist_parsed if @cached_whitelist_raw == current_raw
        @cached_whitelist_raw = current_raw
        @cached_whitelist_parsed = current_raw.split("|").map(&:strip).reject(&:empty?).filter_map do |entry|
          begin
            IPAddr.new(entry)
          rescue StandardError
            entry
          end
        end.freeze
      end
    end

    def self.is_whitelisted_ip?(ip_address)
      return false if ip_address.blank?
      ip_str = ip_address.to_s

      begin
        parsed = IPAddr.new(ip_str)
        return true if parsed.loopback? || (parsed.respond_to?(:private?) && parsed.private?) || (parsed.respond_to?(:link_local?) && parsed.link_local?)
      rescue StandardError
        # Proceed with normal whitelist check if parsing fails
      end

      parsed_whitelisted_ips.any? do |entry|
        if entry.is_a?(IPAddr)
          begin
            entry.include?(ip_str)
          rescue StandardError
            false
          end
        else
          entry == ip_str
        end
      end
    end

    def self.create_challenge(ip_address, scope = "visitor")
      return nil if ip_address.blank?
      challenge_id = SecureRandom.hex(24)
      valid_scope = VALID_SCOPES.include?(scope.to_s) ? scope.to_s : "visitor"
      payload = { ip: ip_address.to_s, scope: valid_scope, created_at: Time.now.utc.iso8601 }.to_json
      Discourse.redis.setex("proxytracer:chal:#{challenge_id}", 600, payload)
      challenge_id
    rescue StandardError => e
      Rails.logger.warn("[ProxyTracer] create challenge error: #{e.message}")
      nil
    end

    def self.consume_challenge(challenge_id, ip_address)
      return nil if challenge_id.blank? || ip_address.blank?
      return nil unless challenge_id.to_s.match?(CHALLENGE_REGEX)

      key = "proxytracer:chal:#{challenge_id}"
      prefixed_key = Discourse.redis.respond_to?(:namespace_key) ? Discourse.redis.namespace_key(key) : key
      lua_script = <<~LUA
        local raw = redis.call("GET", KEYS[1])
        if raw == false or not raw then return nil end
        redis.call("DEL", KEYS[1])
        return raw
      LUA

      raw = Discourse.redis.eval(lua_script, [prefixed_key], [])
      return nil if raw.blank?

      data = begin
        JSON.parse(raw)
      rescue JSON::ParserError
        nil
      end
      return nil if data.blank?
      return nil unless data["ip"] == ip_address.to_s

      valid_scope = data["scope"].to_s
      VALID_SCOPES.include?(valid_scope) ? valid_scope : "visitor"
    rescue StandardError => e
      Rails.logger.warn("[ProxyTracer] consume challenge error: #{e.message}")
      nil
    end

    def self.is_ip_cleared?(ip_address, clearance_token, context = nil)
      return false if ip_address.blank? || clearance_token.blank?
      return false unless SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha"

      key = clearance_key(clearance_token)
      return false if key.blank?

      stored_val = Discourse.redis.get(key)
      return false if stored_val.blank?

      data = begin
        JSON.parse(stored_val)
      rescue JSON::ParserError
        nil
      end
      return false if data.blank?
      return false unless data["ip"] == ip_address.to_s

      active_scopes = Array(data["scopes"] || data["scope"]).map(&:to_s)
      req_context = context.to_s.presence || "visitor"

      case req_context
      when "visitor"
        active_scopes.any? { |s| VALID_SCOPES.include?(s) }
      when "forgot_password"
        active_scopes.include?("forgot_password")
      when "email_login"
        active_scopes.include?("email_login")
      when "login"
        active_scopes.include?("login") || active_scopes.include?("auth")
      when "signup"
        active_scopes.include?("signup") || active_scopes.include?("auth")
      when "auth"
        if SiteSetting.Strict_Auth_Verification
          active_scopes.include?("auth") || active_scopes.include?("login") || active_scopes.include?("signup")
        else
          true
        end
      else
        active_scopes.include?(req_context)
      end
    rescue StandardError => e
      Rails.logger.warn("[ProxyTracer] clearance check error: #{e.message}")
      false
    end

    def self.set_ip_clearance(ip_address, scope = "auth", existing_token = nil)
      return nil if ip_address.blank?
      valid_scope = VALID_SCOPES.include?(scope.to_s) ? scope.to_s : "visitor"

      scopes = [valid_scope]
      if existing_token.present? && existing_token.to_s.match?(CLEARANCE_REGEX)
        existing_key = clearance_key(existing_token)
        if existing_key.present?
          existing_val = Discourse.redis.get(existing_key)
          if existing_val.present?
            begin
              existing_data = JSON.parse(existing_val)
              if existing_data["ip"] == ip_address.to_s
                prev_scopes = Array(existing_data["scopes"] || existing_data["scope"]).map(&:to_s)
                scopes = (prev_scopes + [valid_scope]).uniq
              end
            rescue JSON::ParserError
            end
          end
        end
      end

      token = (existing_token.present? && existing_token.to_s.match?(CLEARANCE_REGEX)) ? existing_token : SecureRandom.hex(24)
      key = clearance_key(token)
      return nil if key.blank?

      hours = [[SiteSetting.ProxyTracer_Captcha_Clearance_hours.to_i, 1].max, 168].min
      ttl = hours * 3600
      payload = {
        ip: ip_address.to_s,
        scope: valid_scope,
        scopes: scopes,
        issued_at: Time.now.utc.iso8601
      }.to_json

      Discourse.redis.setex(key, ttl, payload)
      token
    rescue StandardError => e
      Rails.logger.warn("[ProxyTracer] set clearance error: #{e.message}")
      nil
    end

    def self.increment_daily_stats(is_proxy)
      date_key = Date.current.iso8601
      days = [[SiteSetting.ProxyTracer_Stats_TTL_days.to_i, 1].max, 7305].min
      ttl = days.days.to_i

      Discourse.redis.pipelined do |pipeline|
        pipeline.incr("proxytracer:stats:#{date_key}:requests")
        pipeline.expire("proxytracer:stats:#{date_key}:requests", ttl)

        if is_proxy
          pipeline.incr("proxytracer:stats:#{date_key}:detections")
          pipeline.expire("proxytracer:stats:#{date_key}:detections", ttl)
        end
      end
    rescue StandardError => e
      Rails.logger.warn("[ProxyTracer] increment_daily_stats error: #{e.message}")
    end

    def self.log_block(ip, username, action)
      sanitized_user = username.to_s.truncate(64).gsub(/[[:cntrl:]]/, "") if username.present?
      log_entry = {
        timestamp: Time.zone.now.iso8601,
        ip: ip.to_s,
        username: SiteSetting.ProxyTracer_Log_Usernames ? sanitized_user : nil,
        action: action.to_s
      }.to_json

      Discourse.redis.pipelined do |pipeline|
        pipeline.lpush("proxytracer:logs", log_entry)
        pipeline.ltrim("proxytracer:logs", 0, 499)
      end
    rescue StandardError => e
      Rails.logger.warn("[ProxyTracer] log_block error: #{e.message}")
    end

    def self.record_api_error(ip_address)
      circuit_key = "proxytracer:api_error:#{ip_address}"
      Discourse.redis.setex(circuit_key, 60, "1") rescue nil

      lua_script = <<~LUA
        local count = redis.call("INCR", KEYS[1])
        if count == 1 then
          redis.call("EXPIRE", KEYS[1], tonumber(ARGV[1]))
        end
        if count >= tonumber(ARGV[2]) then
          redis.call("SET", KEYS[2], "1", "EX", tonumber(ARGV[3]))
        end
        return count
      LUA

      k1 = "{proxytracer:api_error}:count"
      k2 = "{proxytracer:api_error}:global"
      pk1 = Discourse.redis.respond_to?(:namespace_key) ? Discourse.redis.namespace_key(k1) : k1
      pk2 = Discourse.redis.respond_to?(:namespace_key) ? Discourse.redis.namespace_key(k2) : k2

      Discourse.redis.eval(
        lua_script,
        [pk1, pk2],
        [60, CIRCUIT_BREAKER_THRESHOLD, CIRCUIT_BREAKER_TTL]
      )
    rescue StandardError
      nil
    end

    def self.is_raw_proxy_ip?(ip_address)
      return false unless SiteSetting.proxytracer_enabled
      return false if ip_address.blank?

      api_key = SiteSetting.ProxyTracer_API_Key
      return false if api_key.blank?
      return false if is_whitelisted_ip?(ip_address)

      cache_key = "proxytracer_ip:#{ip_address}"
      cached_result = begin
        Discourse.redis.get(cache_key)
      rescue StandardError
        nil
      end

      unless cached_result.nil?
        return (cached_result == "true")
      end

      check_ip(ip_address, nil)
    end

    def self.check_ip(ip_address, clearance_token = nil, context = nil)
      return false unless SiteSetting.proxytracer_enabled
      return false if ip_address.blank?

      if SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha" && clearance_token.present? && is_ip_cleared?(ip_address, clearance_token, context)
        return false
      end

      api_key = SiteSetting.ProxyTracer_API_Key
      return false if api_key.blank?
      return false if is_whitelisted_ip?(ip_address)

      cache_key = "proxytracer_ip:#{ip_address}"
      cached_result = begin
        Discourse.redis.get(cache_key)
      rescue StandardError => e
        nil
      end

      unless cached_result.nil?
        is_proxy = (cached_result == "true")
        increment_daily_stats(is_proxy)
        return is_proxy
      end

      # Global Circuit breaker: if upstream API has repeated recent failures
      has_global_error = begin
        Discourse.redis.get("{proxytracer:api_error}:global").present? || Discourse.redis.get("proxytracer:api_error:global").present?
      rescue StandardError
        false
      end
      return !SiteSetting.Fail_Open_on_Error if has_global_error

      # Per-IP Circuit breaker: if recent API call failed for this IP
      circuit_key = "proxytracer:api_error:#{ip_address}"
      has_recent_error = begin
        Discourse.redis.get(circuit_key).present?
      rescue StandardError
        false
      end
      return !SiteSetting.Fail_Open_on_Error if has_recent_error

      timeout_ms = [[SiteSetting.API_Timeout_ms.to_i, 250].max, 5000].min
      timeout_seconds = timeout_ms / 1000.0
      open_timeout_seconds = [[timeout_seconds * 0.5, 0.25].max, timeout_seconds].min

      begin
        canonical_ip = ip_address.to_s
        encoded_ip = ERB::Util.url_encode(canonical_ip)
        uri = URI.parse("#{API_ENDPOINT}#{encoded_ip}")

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.open_timeout = open_timeout_seconds
        http.read_timeout = timeout_seconds

        request = Net::HTTP::Get.new(uri.request_uri)
        request["Authorization"] = "Bearer #{api_key}"
        request["User-Agent"] = "discourse-proxytracer/0.1.2 (+https://github.com/proxytracer/discourse-proxytracer)"
        request["Accept"] = "application/json"

        response = http.request(request)

        if response.is_a?(Net::HTTPSuccess)
          data = JSON.parse(response.body)
          is_proxy = data["proxy"] == true

          ttl_hours = [[SiteSetting.Cache_Duration_hours.to_i, 1].max, 720].min
          ttl_seconds = ttl_hours * 3600

          begin
            Discourse.redis.setex(cache_key, ttl_seconds, is_proxy.to_s)
          rescue StandardError => e
            Rails.logger.warn("[ProxyTracer] Redis cache write error: #{e.message}")
          end

          increment_daily_stats(is_proxy)
          return is_proxy
        else
          Rails.logger.warn("[ProxyTracer] API HTTP error: #{response.code} for IP #{ip_address}")
          record_api_error(ip_address)
          return !SiteSetting.Fail_Open_on_Error
        end
      rescue StandardError => e
        Rails.logger.error("[ProxyTracer] Lookup Exception for #{ip_address}: #{e.class} - #{e.message}")
        record_api_error(ip_address)
        return !SiteSetting.Fail_Open_on_Error
      end
    end
  end
end
