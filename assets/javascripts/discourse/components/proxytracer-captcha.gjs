import Component from "@glimmer/component";
import { tracked } from "@glimmer/tracking";
import { action } from "@ember/object";
import { next } from "@ember/runloop";
import { service } from "@ember/service";
import loadScript from "discourse/lib/load-script";
import { ajax } from "discourse/lib/ajax";

const HCAPTCHA_SCRIPT_URL = "https://hcaptcha.com/1/api.js?render=explicit";
const TURNSTILE_SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

export default class ProxyTracerCaptcha extends Component {
  @service siteSettings;

  @tracked isProxy = false;
  @tracked checked = false;
  @tracked verified = false;
  @tracked loading = false;
  @tracked errorMessage = "";
  @tracked challengeId = null;

  widgetContainerId = `pt-captcha-${Math.random().toString(36).substring(2, 10)}`;
  widgetId = null;
  retryTimer = null;

  get isEnabled() {
    const action = (
      this.siteSettings.ProxyTracer_Action ||
      this.siteSettings.proxytracer_action ||
      this.siteSettings.proxy_tracer_action ||
      ""
    ).toLowerCase();
    const key = this.siteKey;
    const enabled = this.siteSettings.proxytracer_enabled !== false;
    return enabled && action === "captcha" && Boolean(key) && this.isProxy;
  }

  get provider() {
    return (
      this.siteSettings.ProxyTracer_Captcha_Provider ||
      this.siteSettings.proxytracer_captcha_provider ||
      this.siteSettings.proxy_tracer_captcha_provider ||
      "turnstile"
    ).toLowerCase();
  }

  get context() {
    return this.args.context || "login";
  }

  get siteKey() {
    return (
      this.args.siteKey ||
      this.siteSettings.ProxyTracer_Captcha_Site_Key ||
      this.siteSettings.proxytracer_captcha_site_key ||
      this.siteSettings.proxy_tracer_captcha_site_key ||
      ""
    );
  }

  get showBranding() {
    return (
      this.siteSettings.ProxyTracer_Show_Branding !== false &&
      this.siteSettings.proxytracer_show_branding !== false
    );
  }

  constructor() {
    super(...arguments);
    this.checkIpStatus();
  }

  willDestroy() {
    super.willDestroy(...arguments);
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    try {
      if (this.provider === "hcaptcha" && window.hcaptcha && this.widgetId !== null) {
        if (typeof window.hcaptcha.remove === "function") {
          window.hcaptcha.remove(this.widgetId);
        } else {
          window.hcaptcha.reset(this.widgetId);
        }
      } else if (this.provider === "turnstile" && window.turnstile && this.widgetId !== null) {
        if (typeof window.turnstile.remove === "function") {
          window.turnstile.remove(this.widgetId);
        } else {
          window.turnstile.reset(this.widgetId);
        }
      }
    } catch (e) {
      // ignore cleanup errors
    }
  }

  resetWidget() {
    try {
      if (this.provider === "hcaptcha" && window.hcaptcha && this.widgetId !== null) {
        window.hcaptcha.reset(this.widgetId);
      } else if (this.provider === "turnstile" && window.turnstile && this.widgetId !== null) {
        window.turnstile.reset(this.widgetId);
      }
    } catch (e) {
      // ignore reset errors
    }
  }

  async checkIpStatus() {
    if (this.isDestroying || this.isDestroyed) return;

    const action = (
      this.siteSettings.ProxyTracer_Action ||
      this.siteSettings.proxytracer_action ||
      this.siteSettings.proxy_tracer_action ||
      ""
    ).toLowerCase();

    if (action !== "captcha" || !this.siteKey) {
      this.checked = true;
      return;
    }

    try {
      const res = await ajax(`/proxytracer/check-status?context=${encodeURIComponent(this.context)}`);
      if (this.isDestroying || this.isDestroyed) return;
      this.checked = true;
      if (res?.required) {
        this.isProxy = true;
        this.challengeId = res.challenge_id;
        this.initWidget();
      }
    } catch (err) {
      if (this.isDestroying || this.isDestroyed) return;
      this.checked = true;
    }
  }

  async initWidget() {
    if (this.isDestroying || this.isDestroyed) return;

    try {
      const url = this.provider === "hcaptcha" ? HCAPTCHA_SCRIPT_URL : TURNSTILE_SCRIPT_URL;
      await loadScript(url);
      if (this.isDestroying || this.isDestroyed) return;
      next(() => {
        if (this.isDestroying || this.isDestroyed) return;
        this.renderWidget();
      });
    } catch (err) {
      if (this.isDestroying || this.isDestroyed) return;
      console.error("[ProxyTracer] Failed to load CAPTCHA script:", err);
      this.errorMessage = "Failed to load security verification. Please refresh.";
    }
  }

  renderWidget(attempts = 0) {
    if (this.isDestroying || this.isDestroyed) return;

    const container = document.getElementById(this.widgetContainerId);
    if (!container) {
      if (attempts < 10) {
        this.retryTimer = setTimeout(() => {
          this.renderWidget(attempts + 1);
        }, 100);
      }
      return;
    }
    this.executeRender(container);
  }

  executeRender(container) {
    if (this.widgetId !== null || !this.isEnabled || this.isDestroying || this.isDestroyed) {
      return;
    }

    try {
      if (this.provider === "hcaptcha" && window.hcaptcha) {
        this.widgetId = window.hcaptcha.render(container, {
          sitekey: this.siteKey,
          callback: (token) => this.handleVerify(token),
          "expired-callback": () => {
            this.verified = false;
          },
          "error-callback": (err) => {
            this.verified = false;
            this.errorMessage = "Security verification error. Please refresh.";
          },
        });
      } else if (this.provider === "turnstile" && window.turnstile) {
        this.widgetId = window.turnstile.render(container, {
          sitekey: this.siteKey,
          callback: (token) => this.handleVerify(token),
          "expired-callback": () => {
            this.verified = false;
          },
          "error-callback": (errCode) => {
            this.verified = false;
            this.errorMessage = `Security check error (${errCode || "network"}). Please refresh.`;
          },
        });
      }
    } catch (err) {
      console.error("[ProxyTracer] Error rendering CAPTCHA widget:", err);
    }

    const attachButtonGuard = () => {
      const btn = document.getElementById("login-button");
      if (btn && !btn.dataset.ptGuardAttached) {
        btn.dataset.ptGuardAttached = "true";
        btn.addEventListener(
          "click",
          (e) => {
            if (this.isEnabled && !this.verified) {
              e.preventDefault();
              e.stopPropagation();
              e.stopImmediatePropagation();
              this.errorMessage = "⚠️ Security check required: Please complete the CAPTCHA above before proceeding.";
              const el = document.getElementById(this.widgetContainerId);
              if (el) {
                el.scrollIntoView({ behavior: "smooth", block: "center" });
              }
            }
          },
          true
        );
      }
    };
    attachButtonGuard();
  }

  async refreshChallengeAndReset() {
    try {
      const res = await ajax(`/proxytracer/check-status?context=${encodeURIComponent(this.context)}`);
      if (res?.challenge_id) {
        this.challengeId = res.challenge_id;
      }
    } catch (e) {}
    this.resetWidget();
  }

  @action
  async handleVerify(token) {
    if (!token || this.isDestroying || this.isDestroyed) return;

    this.loading = true;
    this.errorMessage = "";

    try {
      const response = await ajax("/proxytracer/verify-captcha", {
        type: "POST",
        data: {
          token,
          challenge_id: this.challengeId,
        },
      });

      if (this.isDestroying || this.isDestroyed) return;

      if (response?.success) {
        this.errorMessage = "";
        this.verified = true;
      } else {
        this.errorMessage = response?.error || "Security verification failed. Please try again.";
        await this.refreshChallengeAndReset();
      }
    } catch (err) {
      if (this.isDestroying || this.isDestroyed) return;
      this.errorMessage = err?.jqXHR?.responseJSON?.error || "Verification failed. Please try again.";
      await this.refreshChallengeAndReset();
    } finally {
      if (!this.isDestroying && !this.isDestroyed) {
        this.loading = false;
      }
    }
  }

  <template>
    {{#if this.isEnabled}}
      <div class="proxytracer-captcha-wrapper" style="margin: 0.75rem 0; text-align: center;">
        <div
          id={{this.widgetContainerId}}
          class="proxytracer-captcha-container"
          style="display: flex; justify-content: center; min-height: 65px;"
        ></div>

        {{#if this.errorMessage}}
          <div class="alert alert-error" style="margin-top: 0.5rem; font-size: 0.875rem;">
            {{this.errorMessage}}
          </div>
        {{/if}}

        {{#if this.verified}}
          <div class="proxytracer-captcha-success" style="color: var(--success, #22c55e); font-size: 0.875rem; margin-top: 0.25rem;">
            ✓ Security check verified
          </div>
        {{/if}}

        {{#if this.showBranding}}
          <div class="proxytracer-branding-note" style="font-size: 0.75rem; color: var(--primary-medium); margin-top: 0.35rem; display: flex; align-items: center; justify-content: center; gap: 0.3rem;">
            <svg style="width: 12px; height: 12px; color: var(--tertiary);" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
            </svg>
            <span>Protected by <a href="https://proxytracer.com" target="_blank" rel="noopener noreferrer" style="color: var(--tertiary); font-weight: 600; text-decoration: none;">ProxyTracer</a></span>
          </div>
        {{/if}}
      </div>
    {{/if}}
  </template>
}
