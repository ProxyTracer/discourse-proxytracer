# frozen_string_literal: true

# name: discourse-proxytracer
# about: Automatically block users behind a VPN, Tor node or proxy from registering, logging in, or viewing your Discourse forum depending on your choice.
# version: 0.1.2
# authors: ProxyTracer
# url: https://github.com/proxytracer/discourse-proxytracer

enabled_site_setting :proxytracer_enabled

register_svg_icon "shield-halved" if respond_to?(:register_svg_icon)
register_svg_icon "shield" if respond_to?(:register_svg_icon)

extend_content_security_policy(
  script_src: %w[https://challenges.cloudflare.com https://js.hcaptcha.com https://hcaptcha.com https://*.hcaptcha.com https://newassets.hcaptcha.com],
  frame_src: %w[https://challenges.cloudflare.com https://hcaptcha.com https://*.hcaptcha.com https://newassets.hcaptcha.com],
  connect_src: %w[https://challenges.cloudflare.com https://hcaptcha.com https://*.hcaptcha.com https://newassets.hcaptcha.com],
  style_src: %w[https://challenges.cloudflare.com https://hcaptcha.com https://*.hcaptcha.com https://newassets.hcaptcha.com]
) if respond_to?(:extend_content_security_policy)

require_relative "lib/proxy_tracer_blocker/proxy_tracer_api"
require_relative "lib/proxy_tracer_blocker/captcha_verifier"
require_relative "lib/proxy_tracer_blocker/checkpoint_page"

after_initialize do
  require_relative "app/controllers/proxy_tracer_blocker/admin_proxy_tracer_controller"
  require_relative "app/controllers/proxy_tracer_blocker/captcha_controller"

  add_admin_route "proxytracer.admin_title", "discourse-proxytracer", use_new_show_route: true

  Discourse::Application.routes.append do
    get "/proxytracer/check-status" => "proxy_tracer_blocker/captcha#check_status"
    get "/proxytracer/challenge" => "proxy_tracer_blocker/captcha#challenge"
    post "/proxytracer/verify-captcha" => "proxy_tracer_blocker/captcha#verify"

    scope constraints: AdminConstraint.new do
      get "/admin/plugins/discourse-proxytracer" => "admin/admin#index"
      get "/admin/plugins/discourse-proxytracer/stats" => "admin/admin#index"
      get "/admin/plugins/discourse-proxytracer/logs" => "admin/admin#index"
      get "/admin/plugins/discourse-proxytracer/settings" => "admin/admin#index"

      get "/admin/plugins/discourse-proxytracer-blocker" => "admin/admin#index"
      get "/admin/plugins/discourse-proxytracer-blocker/stats" => "admin/admin#index"
      get "/admin/plugins/discourse-proxytracer-blocker/logs" => "admin/admin#index"
      get "/admin/plugins/discourse-proxytracer-blocker/settings" => "admin/admin#index"

      get "/admin/plugins/proxytracer/stats" => "proxy_tracer_blocker/admin_proxy_tracer#stats"
      get "/admin/plugins/proxytracer/logs" => "proxy_tracer_blocker/admin_proxy_tracer#logs"
    end
  end

  class ::ProblemCheck::ProxyTracerMissingKey < ::ProblemCheck
    self.priority = "high"

    def call
      return no_problem unless SiteSetting.proxytracer_enabled
      return no_problem if SiteSetting.ProxyTracer_API_Key.present?

      problem
    end
  end

  register_problem_check ::ProblemCheck::ProxyTracerMissingKey

  class ::ProblemCheck::ProxyTracerMissingCaptchaKey < ::ProblemCheck
    self.priority = "high"

    def call
      return no_problem unless SiteSetting.proxytracer_enabled
      return no_problem unless SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha"
      return no_problem if SiteSetting.ProxyTracer_Captcha_Site_Key.present? && SiteSetting.ProxyTracer_Captcha_Secret_Key.present?

      problem
    end
  end

  register_problem_check ::ProblemCheck::ProxyTracerMissingCaptchaKey

  PROXYTRACER_SETTINGS = Set.new(%w[
    proxytracer_enabled
    proxytracer_api_key
    api_timeout_ms
    cache_duration_hours
    fail_open_on_error
    enabled_during_signup
    enabled_during_login
    enabled_for_all_visitors
    strict_auth_verification
    proxytracer_action
    proxytracer_captcha_provider
    proxytracer_captcha_site_key
    proxytracer_captcha_secret_key
    proxytracer_captcha_clearance_hours
    proxytracer_show_branding
    whitelisted_ips
  ]).freeze

  DiscourseEvent.on(:site_setting_changed) do |name|
    if PROXYTRACER_SETTINGS.include?(name.to_s.downcase)
      begin
        patterns = [
          "proxytracer_ip:*",
          "proxytracer:clearance:*",
          "proxytracer:chal:*",
          "proxytracer:api_error:*",
          "{proxytracer:api_error}:*"
        ]
        patterns.each do |pattern|
          batch = []
          Discourse.redis.scan_each(match: pattern, count: 500) do |key|
            batch << key
            if batch.size >= 500
              Discourse.redis.pipelined do |pipeline|
                batch.each { |k| pipeline.del(k) }
              end
              batch.clear
            end
          end
          if batch.any?
            Discourse.redis.pipelined do |pipeline|
              batch.each { |k| pipeline.del(k) }
            end
          end
        end
      rescue StandardError => e
        Rails.logger.warn("ProxyTracer cache clear error: #{e.message}")
      end
    end
  end

  reloadable_patch do |plugin|
    ::UsersController.class_eval do
      prepend_before_action :check_proxytracer_ip_on_signup, only: %i[create email_login password_reset_update perform_account_activation]

      def check_proxytracer_ip_on_signup
        is_signup = %w[create perform_account_activation].include?(action_name)
        is_login = %w[email_login password_reset_update].include?(action_name)

        return if is_signup && !SiteSetting.Enabled_during_Signup
        return if is_login && !SiteSetting.Enabled_during_Login
        return unless is_signup || is_login

        ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
        if ip_to_check.blank?
          return render json: { success: false, error: "Invalid client IP address." }, status: :forbidden
        end

        clearance_token = cookies[:proxytracer_clearance]
        req_context = if action_name == "email_login"
          "email_login"
        elsif action_name == "password_reset_update"
          "forgot_password"
        elsif is_signup
          "signup"
        else
          "auth"
        end
        is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check, clearance_token, req_context)

        if is_proxy
          username = (params[:username] || params[:login]).to_s.truncate(64).gsub(/[[:cntrl:]]/, "")
          ProxyTracerBlocker::ProxyTracerApi.log_block(ip_to_check, username, action_name)
          Rails.logger.warn("[ProxyTracer] Auth check BLOCKED for action '#{action_name}' from #{ip_to_check}")

          msg = if SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha" && SiteSetting.ProxyTracer_Captcha_Site_Key.present?
            "⚠️ Security check required: Please complete the CAPTCHA above before proceeding."
          else
            SiteSetting.Block_Message
          end

          if action_name == "email_login" || action_name == "password_reset_update"
            render_json_error(msg, status: 422)
          elsif action_name == "perform_account_activation"
            flash[:error] = msg
            redirect_to path("/login")
          elsif action_name == "create"
            render json: { success: false, message: msg }
          else
            render json: { success: false, message: msg }, status: :forbidden
          end
        end
      end
    end

    ::SessionController.class_eval do
      prepend_before_action :check_proxytracer_ip_on_login, only: %i[
        create
        passkey_login
        forgot_password
        sso
        sso_login
        email_login
        one_time_password
        sso_provider
      ]

      def check_proxytracer_ip_on_login
        unless SiteSetting.Enabled_during_Login
          return
        end

        ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
        if ip_to_check.blank?
          return render json: { error: "Invalid client IP address." }, status: :forbidden
        end

        clearance_token = cookies[:proxytracer_clearance]
        req_context = if action_name == "forgot_password"
          "forgot_password"
        elsif action_name == "email_login"
          "email_login"
        else
          "login"
        end
        is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check, clearance_token, req_context)

        if is_proxy
          login = params[:login].to_s.truncate(64).gsub(/[[:cntrl:]]/, "")
          ProxyTracerBlocker::ProxyTracerApi.log_block(ip_to_check, login, action_name)
          Rails.logger.warn("[ProxyTracer] Auth check blocked for action '#{action_name}' from #{ip_to_check}")

          msg = if SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha" && SiteSetting.ProxyTracer_Captcha_Site_Key.present?
            "⚠️ Security check required: Please complete the CAPTCHA above before proceeding."
          else
            SiteSetting.Block_Message
          end

          if action_name == "forgot_password"
            render_json_error(msg, status: 422)
          elsif action_name == "sso" || action_name == "sso_login" || action_name == "sso_provider"
            flash[:error] = msg
            redirect_to path("/login")
          elsif action_name == "create" || action_name == "passkey_login"
            render json: { error: msg }
          else
            render json: { error: msg }, status: :forbidden
          end
        end
      end
    end

    if defined?(::Users::AssociateAccountsController)
      ::Users::AssociateAccountsController.class_eval do
        prepend_before_action :check_proxytracer_ip_on_associate, only: [:connect]

        def check_proxytracer_ip_on_associate
          return unless SiteSetting.Enabled_during_Login || SiteSetting.Enabled_during_Signup

          ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
          if ip_to_check.blank?
            flash[:error] = "Invalid client IP address."
            return redirect_to path("/login")
          end

          clearance_token = cookies[:proxytracer_clearance]
          is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check, clearance_token, "auth")

          if is_proxy
            username = current_user&.username.to_s.truncate(64).gsub(/[[:cntrl:]]/, "")
            ProxyTracerBlocker::ProxyTracerApi.log_block(ip_to_check, username, "associate_account")
            Rails.logger.warn("[ProxyTracer] Associate account blocked for #{ip_to_check}")

            if SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha" && SiteSetting.ProxyTracer_Captcha_Site_Key.present?
              redirect_to path("/proxytracer/challenge?return_to=#{CGI.escape(request.fullpath)}")
            else
              flash[:error] = SiteSetting.Block_Message
              redirect_to path("/login")
            end
          end
        end
      end
    end

    if defined?(::UsersEmailController)
      ::UsersEmailController.class_eval do
        prepend_before_action :check_proxytracer_ip_on_email_confirm, only: %i[confirm_old_email confirm_new_email]

        def check_proxytracer_ip_on_email_confirm
          return unless SiteSetting.Enabled_during_Login

          ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
          if ip_to_check.blank?
            return render json: { error: "Invalid client IP address." }, status: :forbidden
          end

          clearance_token = cookies[:proxytracer_clearance]
          is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check, clearance_token, "auth")

          if is_proxy
            username = current_user&.username.to_s.truncate(64).gsub(/[[:cntrl:]]/, "")
            ProxyTracerBlocker::ProxyTracerApi.log_block(ip_to_check, username, action_name)
            Rails.logger.warn("[ProxyTracer] Email confirmation blocked for action '#{action_name}' from #{ip_to_check}")

            render json: { error: SiteSetting.Block_Message }, status: :forbidden
          end
        end
      end
    end

    if defined?(::InvitesController)
      ::InvitesController.class_eval do
        prepend_before_action :check_proxytracer_ip_on_invite, only: %i[perform_accept_invitation]

        def check_proxytracer_ip_on_invite
          unless SiteSetting.Enabled_during_Signup
            return
          end

          ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
          if ip_to_check.blank?
            return render json: { success: false, error: "Invalid client IP address." }, status: :forbidden
          end

          clearance_token = cookies[:proxytracer_clearance]
          is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check, clearance_token, "auth")

          if is_proxy
            username = params[:username].to_s.truncate(64).gsub(/[[:cntrl:]]/, "")
            ProxyTracerBlocker::ProxyTracerApi.log_block(ip_to_check, username, "invite_accept")
            Rails.logger.warn("[ProxyTracer] Invite acceptance BLOCKED for #{ip_to_check}")

            msg = if SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha" && SiteSetting.ProxyTracer_Captcha_Site_Key.present?
              "⚠️ Security check required: Please complete the security check to accept this invitation."
            else
              SiteSetting.Block_Message
            end

            render json: { success: false, message: msg, error: msg }, status: :forbidden
          end
        end
      end
    end

    if defined?(::Users::OmniauthCallbacksController)
      ::Users::OmniauthCallbacksController.class_eval do
        prepend_before_action :check_proxytracer_ip_on_oauth, only: [:complete]

        def check_proxytracer_ip_on_oauth
          unless SiteSetting.Enabled_during_Login || SiteSetting.Enabled_during_Signup
            return
          end

          ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
          if ip_to_check.blank?
            flash[:error] = "Invalid client IP address."
            return redirect_to path("/login")
          end

          clearance_token = cookies[:proxytracer_clearance]
          is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check, clearance_token, "auth")

          if is_proxy
            ProxyTracerBlocker::ProxyTracerApi.log_block(ip_to_check, "oauth_user", "oauth_login")
            Rails.logger.warn("[ProxyTracer] OAuth login blocked for #{ip_to_check}")

            if SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha" && SiteSetting.ProxyTracer_Captcha_Site_Key.present?
              redirect_to path("/proxytracer/challenge?return_to=#{CGI.escape(request.fullpath)}")
            else
              flash[:error] = SiteSetting.Block_Message
              redirect_to path("/login")
            end
          end
        end
      end
    end

    ::ApplicationController.class_eval do
      prepend_before_action :check_proxytracer_global_access

      def check_proxytracer_global_access
        return unless SiteSetting.Enabled_for_All_Visitors

        path = request.path.to_s
        base = defined?(Discourse) ? Discourse.base_path.to_s.chomp("/") : ""
        return if path.start_with?(
          "#{base}/proxytracer/",
          "#{base}/message-bus/",
          "#{base}/theme-javascripts/",
          "#{base}/stylesheets/",
          "#{base}/letter_avatar_proxy/",
          "#{base}/svg-sprite/",
          "#{base}/extra-locales/",
          "#{base}/assets/",
          "#{base}/uploads/",
          "#{base}/user_avatar/",
          "#{base}/favicon/",
          "#{base}/srv/status",
          "#{base}/robots.txt",
          "#{base}/manifest.webmanifest",
          "#{base}/service-worker.js"
        ) || path == "#{base}/session/csrf"

        ip_to_check = ProxyTracerBlocker::ProxyTracerApi.extract_client_ip(request)
        if ip_to_check.blank?
          response.headers["Cache-Control"] = "no-store, no-cache, private"
          response.headers["Vary"] = "Cookie"
          if request.format.json?
            return render json: { error: "Invalid client IP address." }, status: :forbidden
          else
            return render plain: "Invalid client IP address.", status: :forbidden
          end
        end

        clearance_token = cookies[:proxytracer_clearance]
        is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check, clearance_token, "visitor")

        if is_proxy
          username = current_user&.username.to_s.truncate(64).gsub(/[[:cntrl:]]/, "") if current_user
          ProxyTracerBlocker::ProxyTracerApi.log_block(ip_to_check, username, "visit")

          response.headers["Cache-Control"] = "no-store, no-cache, private"
          response.headers["Vary"] = "Cookie"

          if SiteSetting.ProxyTracer_Action.to_s.downcase == "captcha" && SiteSetting.ProxyTracer_Captcha_Site_Key.present?
            if request.format.html?
              begin
                RateLimiter.new(nil, "proxytracer-challenge-#{ip_to_check}", 20, 1.minute).performed!
              rescue RateLimiter::LimitExceeded
                response.headers["Cache-Control"] = "no-store, no-cache, private"
                return render plain: "Rate limit exceeded. Please wait a moment.", status: :too_many_requests
              end
              csp_nonce = ContentSecurityPolicy.nonce_placeholder(response.headers)
              challenge_id = ProxyTracerBlocker::ProxyTracerApi.create_challenge(ip_to_check, "visitor")
              render html: ProxyTracerBlocker::CheckpointPage.render_html(
                SiteSetting.ProxyTracer_Captcha_Site_Key,
                SiteSetting.ProxyTracer_Captcha_Provider,
                form_authenticity_token,
                challenge_id,
                request.fullpath,
                csp_nonce
              ).html_safe, layout: false, status: :forbidden
            else
              render json: { error: SiteSetting.Block_Message }, status: :forbidden
            end
          else
            if request.format.json?
              render json: { error: SiteSetting.Block_Message }, status: :forbidden
            else
              render plain: SiteSetting.Block_Message, status: :forbidden
            end
          end
        end
      end
    end
  end
end
