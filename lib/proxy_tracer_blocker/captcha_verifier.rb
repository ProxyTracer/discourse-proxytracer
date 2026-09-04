# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module ProxyTracerBlocker
  class CaptchaVerifier
    TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    HCAPTCHA_URL = "https://hcaptcha.com/siteverify"

    def self.verify(token, remote_ip)
      secret_key = SiteSetting.ProxyTracer_Captcha_Secret_Key
      return false if secret_key.blank? || token.blank?

      provider = SiteSetting.ProxyTracer_Captcha_Provider.to_s.downcase
      url_str = (provider == "hcaptcha") ? HCAPTCHA_URL : TURNSTILE_URL
      uri = URI.parse(url_str)

      timeout_ms = [[SiteSetting.API_Timeout_ms.to_i, 1000].max, 5000].min
      timeout_seconds = timeout_ms / 1000.0

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == "https")
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.open_timeout = [[timeout_seconds * 0.5, 1.0].max, timeout_seconds].min
      http.read_timeout = timeout_seconds

      request = Net::HTTP::Post.new(uri.request_uri)
      request["User-Agent"] = "discourse-proxytracer/0.1.2 (+https://github.com/proxytracer/discourse-proxytracer)"
      request["Accept"] = "application/json"
      request.set_form_data(
        "secret" => secret_key,
        "response" => token,
        "remoteip" => remote_ip.to_s
      )

      response = http.request(request)
      if response.is_a?(Net::HTTPSuccess)
        data = JSON.parse(response.body)
        data["success"] == true
      else
        Rails.logger.warn("ProxyTracer CAPTCHA verification failed with HTTP #{response.code}: #{response.body}")
        false
      end
    rescue StandardError => e
      Rails.logger.error("ProxyTracer CAPTCHA verification exception: #{e.message}")
      false
    end
  end
end
