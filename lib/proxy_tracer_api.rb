require 'net/http'
require 'json'
require 'uri'
require 'ipaddr'

module ProxyTracerBlocker
  class ProxyTracerApi
    API_ENDPOINT = "https://api.proxytracer.com/v1/check/".freeze

    def self.check_ip(ip_address)
      return false unless SiteSetting.proxytracer_enabled

      api_key = SiteSetting.ProxyTracer_API_Key
      return false if api_key.blank?

      whitelist_entries = SiteSetting.Whitelisted_IPs.split('|').map(&:strip).reject(&:empty?)

      is_whitelisted = whitelist_entries.any? do |entry|
        begin
          IPAddr.new(entry).include?(ip_address.to_s)
        rescue IPAddr::InvalidAddressError
          entry == ip_address.to_s
        end
      end

      return false if is_whitelisted

      cache_key = "proxytracer_ip:#{ip_address}"
      cached_result = Discourse.redis.get(cache_key)
      return cached_result == 'true' unless cached_result.nil?

      timeout_ms = SiteSetting.API_Timeout_ms.to_i
      timeout_seconds = timeout_ms > 0 ? (timeout_ms / 1000.0) : 3.0

      uri = URI.parse("#{API_ENDPOINT}#{ip_address}")
      request = Net::HTTP::Get.new(uri)
      request["Authorization"] = "Bearer #{api_key}"

      begin
        response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true, read_timeout: timeout_seconds, open_timeout: timeout_seconds) do |http|
          http.request(request)
        end

        if response.is_a?(Net::HTTPSuccess)
          data = JSON.parse(response.body)
          is_proxy = data['proxy'] == true

          ttl_hours = SiteSetting.Cache_Duration_hours.to_i
          ttl_seconds = ttl_hours > 0 ? (ttl_hours * 3600) : (168 * 3600)

          Discourse.redis.setex(cache_key, ttl_seconds, is_proxy.to_s)
          return is_proxy
        else
          Rails.logger.warn("ProxyTracer API Error: #{response.code} - #{response.message} for IP: #{ip_address}")
          return !SiteSetting.Fail_Open_on_Error
        end
      rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError,
             Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError, StandardError => e
        Rails.logger.error("ProxyTracer Connection Error: #{e.message}")
        return !SiteSetting.Fail_Open_on_Error
      end
    end
  end
end
