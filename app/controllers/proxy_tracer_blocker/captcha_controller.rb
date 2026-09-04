# frozen_string_literal: true

module ::ProxyTracerBlocker
  class CaptchaController < ::ApplicationController
    skip_before_action :check_proxytracer_global_access, raise: false
    skip_before_action :check_xhr, raise: false
    skip_forgery_protection only: %i[check_status verify]

    def check_status
      response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
      response.headers["Vary"] = "Cookie"

      raw_context = params[:context].to_s.presence || "visitor"
      context = ProxyTracerBlocker::ProxyTracerApi::VALID_SCOPES.include?(raw_context) ? raw_context : "visitor"
      ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)

      if ip_to_check.blank?
        return render json: { required: false, error: "Invalid client IP address." }, status: :forbidden
      end

      begin
        RateLimiter.new(nil, "proxytracer-status-#{ip_to_check}", 60, 1.minute).performed!
      rescue RateLimiter::LimitExceeded
        return render json: { required: false, error: "Rate limit exceeded" }, status: :too_many_requests
      end

      unless SiteSetting.proxytracer_enabled && SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha" && SiteSetting.ProxyTracer_Captcha_Site_Key.present?
        return render json: { required: false }
      end

      clearance_token = cookies[:proxytracer_clearance]
      if clearance_token.present? && ProxyTracerBlocker::ProxyTracerApi.is_ip_cleared?(ip_to_check, clearance_token, context)
        return render json: { required: false }
      end

      is_proxy = ProxyTracerBlocker::ProxyTracerApi.is_raw_proxy_ip?(ip_to_check)
      challenge_id = is_proxy ? ProxyTracerBlocker::ProxyTracerApi.create_challenge(ip_to_check, context) : nil

      render json: { required: is_proxy, challenge_id: challenge_id }
    end

    def challenge
      response.headers["Cache-Control"] = "no-store, no-cache, private"
      response.headers["Vary"] = "Cookie"

      unless SiteSetting.proxytracer_enabled
        return render plain: "ProxyTracer is currently disabled.", status: :forbidden
      end

      if SiteSetting.ProxyTracer_Action.to_s.downcase != "captcha" || SiteSetting.ProxyTracer_Captcha_Site_Key.blank?
        return render plain: SiteSetting.Block_Message, status: :forbidden
      end

      ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
      if ip_to_check.blank?
        return render plain: "Invalid client IP address.", status: :forbidden
      end

      clearance_token = cookies[:proxytracer_clearance]
      if clearance_token.present? && ProxyTracerBlocker::ProxyTracerApi.is_ip_cleared?(ip_to_check, clearance_token, "visitor")
        safe_return = ProxyTracerBlocker::CheckpointPage.safe_return_path(params[:return_to])
        return redirect_to(safe_return)
      end

      begin
        RateLimiter.new(nil, "proxytracer-challenge-#{ip_to_check}", 20, 1.minute).performed!
      rescue RateLimiter::LimitExceeded
        return render plain: "Rate limit exceeded. Please wait a moment.", status: :too_many_requests
      end

      challenge_id = ProxyTracerBlocker::ProxyTracerApi.create_challenge(ip_to_check, "visitor")

      csp_nonce = ContentSecurityPolicy.nonce_placeholder(response.headers)
      safe_return = ProxyTracerBlocker::CheckpointPage.safe_return_path(params[:return_to])

      response.headers["Cache-Control"] = "no-store, no-cache, private"
      response.headers["Vary"] = "Cookie"

      render html: ProxyTracerBlocker::CheckpointPage.render_html(
        SiteSetting.ProxyTracer_Captcha_Site_Key,
        SiteSetting.ProxyTracer_Captcha_Provider,
        form_authenticity_token,
        challenge_id,
        safe_return,
        csp_nonce
      ).html_safe, layout: false, status: :forbidden
    end

    def verify
      response.headers["Cache-Control"] = "no-store, no-cache, private"

      unless SiteSetting.proxytracer_enabled && SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha"
        return render json: { success: false, error: "CAPTCHA verification is currently disabled." }, status: :unprocessable_entity
      end

      ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
      if ip_to_check.blank?
        return render json: { success: false, error: "Invalid client IP address." }, status: :bad_request
      end

      begin
        RateLimiter.new(nil, "proxytracer-verify-global", 300, 1.minute).performed!
        RateLimiter.new(nil, "proxytracer-verify-#{ip_to_check}", 15, 1.minute).performed!
      rescue RateLimiter::LimitExceeded
        return render json: { success: false, error: "Too many verification attempts. Please wait a moment." }, status: :too_many_requests
      end

      token = params[:token]
      if token.blank?
        return render json: { success: false, error: "Missing CAPTCHA response token." }, status: :unprocessable_entity
      end

      challenge_id = params[:challenge_id]
      scope = ProxyTracerBlocker::ProxyTracerApi.consume_challenge(challenge_id, ip_to_check)
      if scope.blank?
        return render json: { success: false, error: "Security challenge has expired or is invalid. Please refresh the page." }, status: :unprocessable_entity
      end

      verified = ProxyTracerBlocker::CaptchaVerifier.verify(token, ip_to_check)

      if verified
        clearance_token = ProxyTracerBlocker::ProxyTracerApi.set_ip_clearance(ip_to_check, scope, cookies[:proxytracer_clearance])
        if clearance_token.blank?
          Rails.logger.error("[ProxyTracer] Failed to issue clearance token for #{ip_to_check}")
          return render json: { success: false, error: "Failed to issue security clearance token. Please try again." }, status: :internal_server_error
        end

        hours = SiteSetting.ProxyTracer_Captcha_Clearance_hours.to_i
        expires_at = hours > 0 ? hours.hours.from_now : 24.hours.from_now

        cookies[:proxytracer_clearance] = {
          value: clearance_token,
          expires: expires_at,
          httponly: true,
          secure: (request.ssl? || SiteSetting.force_https),
          same_site: :lax,
          path: "/"
        }

        Rails.logger.info("[ProxyTracer] CAPTCHA successfully verified for #{ip_to_check} (scope: #{scope})")
        render json: { success: true }
      else
        Rails.logger.warn("[ProxyTracer] CAPTCHA verification rejected by upstream provider for #{ip_to_check}")
        render json: { success: false, error: "CAPTCHA verification failed. Please try again." }, status: :unprocessable_entity
      end
    end
  end
end
