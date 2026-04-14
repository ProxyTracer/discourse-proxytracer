# name: discourse-proxytracer
# about: Automatically block users behind a VPN, Tor node or proxy from registering, logging in, or viewing your Discourse forum depending on your choice.
# version: 0.1.1
# authors: ProxyTracer
# url: https://github.com/proxytracer/discourse-proxytracer
enabled_site_setting :proxytracer_enabled

after_initialize do
  require_relative 'lib/proxy_tracer_api'

  class ::ProblemCheck::ProxyTracerMissingKey < ::ProblemCheck
    self.priority = "high"

    def call
      problem if SiteSetting.ProxyTracer_API_Key.blank?
    end

    private

    def message
      "ProxyTracer is inactive! Please enter your ProxyTracer API Key in the plugin settings to enable proxy and VPN blocking."
    end
  end

  register_problem_check ::ProblemCheck::ProxyTracerMissingKey

  User.class_eval do
    validate :check_proxytracer_ip_on_signup, on: :create

    def check_proxytracer_ip_on_signup
      return unless SiteSetting.Enabled_during_Signup
      return if self.registration_ip_address.blank?

      ip_to_check = self.registration_ip_address.to_s
      is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check)

      if is_proxy
        self.errors.add(:base, SiteSetting.Block_Message)
      end
    end
  end

  require_dependency 'session_controller'

  ::SessionController.class_eval do
    before_action :check_proxytracer_ip_on_login, only: [:create]

    def check_proxytracer_ip_on_login
      return unless SiteSetting.Enabled_during_Login

      ip_to_check = request.remote_ip.to_s
      return if ip_to_check.blank?

      is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check)

      if is_proxy
        render json: { error: SiteSetting.Block_Message }, status: :ok
      end
    end
  end

  require_dependency 'application_controller'

  ::ApplicationController.class_eval do
    before_action :check_proxytracer_global_access

    def check_proxytracer_global_access
      return unless SiteSetting.Enabled_for_All_Visitors

      ip_to_check = request.remote_ip.to_s
      return if ip_to_check.blank?

      is_proxy = ProxyTracerBlocker::ProxyTracerApi.check_ip(ip_to_check)

      if is_proxy
        # Gracefully handle both API/Mobile requests and standard web browser loads
        if request.format.json?
          render json: { error: SiteSetting.Block_Message }, status: :forbidden
        else
          render plain: SiteSetting.Block_Message, status: :forbidden
        end
      end
    end
  end
end
