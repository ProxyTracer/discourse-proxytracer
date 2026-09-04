# frozen_string_literal: true

module ProxyTracerBlocker
  class CheckpointPage
    def self.safe_return_path(raw)
      path = raw.to_s.strip
      return "/" if path.blank? || path.length > 512
      return "/" if path.match?(/[[:cntrl:]]/)
      return "/" unless path.start_with?("/") && !path.start_with?("//") && !path.start_with?("/\\")

      begin
        base_prefix = defined?(Discourse) ? Discourse.base_path : ""
        uri = URI.parse(path)
        return "/" if uri.scheme.present? || uri.host.present?

        clean_path = uri.path.to_s.chomp("/")
        challenge_route = "#{base_prefix}/proxytracer/challenge"

        return "/" if clean_path.casecmp(challenge_route).zero?
        return "/" if clean_path.downcase.start_with?("#{challenge_route}/")
        return "/" if clean_path.downcase.start_with?("#{base_prefix}/proxytracer/")

        result = uri.path.presence || "/"
        result += "?#{uri.query}" if uri.query.present?
        result
      rescue URI::Error
        "/"
      end
    end

    def self.safe_json(str)
      str.to_s.to_json.gsub("</", '<\\/')
    end

    def self.render_html(site_key, provider, csrf_token, challenge_id, return_to = "/", csp_nonce = nil)
      is_hcaptcha = provider.to_s.downcase == "hcaptcha"
      site_name = ERB::Util.html_escape(SiteSetting.title.presence || "Discourse")
      title_text = "Security Verification - #{site_name}"
      escaped_site_key = ERB::Util.html_escape(site_key.to_s.strip)

      logo_url = SiteSetting.site_logo_url.presence
      logo_dark_url = SiteSetting.site_logo_dark_url.presence

      logo_html = if logo_url.present?
        if logo_dark_url.present?
          <<~HTML
            <picture>
              <source srcset="#{ERB::Util.html_escape(logo_dark_url)}" media="(prefers-color-scheme: dark)">
              <img src="#{ERB::Util.html_escape(logo_url)}" alt="#{site_name}" id="site-logo" class="logo-big">
            </picture>
          HTML
        else
          "<img src=\"#{ERB::Util.html_escape(logo_url)}\" alt=\"#{site_name}\" id=\"site-logo\" class=\"logo-big\">"
        end
      else
        <<~HTML
          <svg class="d-icon d-icon-discourse" viewBox="0 0 512 512" fill="currentColor">
            <path d="M256 0C114.6 0 0 114.6 0 256c0 48.7 13.7 94.2 37.3 133L6.9 494.3c-3 9.9 6.2 19.1 16.1 16.1l105.3-30.4C167.8 498.3 213.3 512 256 512c141.4 0 256-114.6 256-256S397.4 0 256 0zm0 432c-38.3 0-74.4-11.4-104.8-31.1l-6.8-4.4-60.6 17.5 17.5-60.6-4.4-6.8C77.4 316.4 66 280.3 66 242 66 137.1 151.1 52 256 52s190 85.1 190 190-85.1 190-190 190z"/>
          </svg>
          <h2 id="site-text-logo">#{site_name}</h2>
        HTML
      end

      nonce_attr = csp_nonce.present? ? "nonce=\"#{ERB::Util.html_escape(csp_nonce)}\"" : ""

      script_tag = if is_hcaptcha
        "<script src=\"https://hcaptcha.com/1/api.js\" async defer #{nonce_attr}></script>"
      else
        "<script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\" async defer #{nonce_attr}></script>"
      end

      missing_key_warning = if escaped_site_key.blank?
        <<~HTML
          <div class="alert alert-error">
            <span>⚠️ Notice: CAPTCHA Site Key is not configured. Please set it in <b>Admin &rarr; Plugins &rarr; ProxyTracer</b>.</span>
          </div>
        HTML
      else
        ""
      end

      show_branding = SiteSetting.ProxyTracer_Show_Branding

      brand_badge_html = if show_branding
        <<~HTML
          <div class="brand-badge">
            <svg viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
            </svg>
            <span>Protected by <strong>ProxyTracer</strong></span>
          </div>
        HTML
      else
        ""
      end

      footer_html = if show_branding
        <<~HTML
          <footer id="footer" class="wrap">
            <p>Protected by <a href="https://proxytracer.com" target="_blank" rel="noopener noreferrer">ProxyTracer</a> &bull; Advanced Proxy & VPN Intelligence</p>
          </footer>
        HTML
      else
        ""
      end

      base_prefix = defined?(Discourse) ? Discourse.base_path : ""
      verify_url = "#{base_prefix}/proxytracer/verify-captcha"
      status_url = "#{base_prefix}/proxytracer/check-status?context=visitor"

      js_return_url = safe_json(safe_return_path(return_to))
      js_site_key = safe_json(site_key.to_s.strip)
      js_csrf_token = safe_json(csrf_token)
      js_challenge_id = safe_json(challenge_id.to_s.strip)
      js_verify_url = safe_json(verify_url)
      js_status_url = safe_json(status_url)

      <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <meta name="robots" content="noindex, nofollow">
          <title>#{title_text}</title>
          <script #{nonce_attr}>
            window.__ptReturnUrl = #{js_return_url};
            window.__ptSiteKey = #{js_site_key};
            window.__ptCsrfToken = #{js_csrf_token};
            window.__ptChallengeId = #{js_challenge_id};
            window.__ptVerifyUrl = #{js_verify_url};
            window.__ptStatusUrl = #{js_status_url};
            window.__ptSubmitting = false;

            function resetCaptchaWidget() {
              window.__ptSubmitting = false;
              try {
                if (typeof hcaptcha !== "undefined") {
                  hcaptcha.reset();
                } else if (typeof turnstile !== "undefined") {
                  turnstile.reset();
                }
              } catch(e) {}

              if (window.__ptStatusUrl) {
                fetch(window.__ptStatusUrl)
                  .then(function(res) { return res.json(); })
                  .then(function(data) {
                    if (data && data.challenge_id) {
                      window.__ptChallengeId = data.challenge_id;
                    }
                  })
                  .catch(function() {});
              }
            }

            window.onCaptchaSuccess = function(token) {
              if (!token) return;
              if (window.__ptSubmitting) return;
              window.__ptSubmitting = true;

              var statusEl = document.getElementById("status");
              if (statusEl) {
                statusEl.innerText = "Verifying security token...";
                statusEl.className = "status-indicator";
              }

              var formData = new FormData();
              formData.append("token", token);
              formData.append("challenge_id", window.__ptChallengeId);
              formData.append("authenticity_token", window.__ptCsrfToken);

              fetch(window.__ptVerifyUrl, {
                method: "POST",
                body: formData,
                headers: {
                  "X-Requested-With": "XMLHttpRequest",
                  "X-CSRF-Token": window.__ptCsrfToken
                }
              })
              .then(function(res) {
                return res.json().catch(function() {
                  return { success: false, error: "Server returned unexpected response (HTTP " + res.status + ")" };
                });
              })
              .then(function(data) {
                if (data && data.success) {
                  if (statusEl) {
                    statusEl.innerText = "✓ Verification successful! Redirecting...";
                    statusEl.className = "status-indicator success";
                  }
                  setTimeout(function() {
                    window.location.replace(window.__ptReturnUrl);
                  }, 350);
                } else {
                  var msg = (data && data.error) ? data.error : "Verification failed. Please try again.";
                  if (statusEl) {
                    statusEl.innerText = msg;
                    statusEl.className = "status-indicator error";
                  }
                  resetCaptchaWidget();
                }
              })
              .catch(function(err) {
                if (statusEl) {
                  statusEl.innerText = "Network error during verification. Please try again.";
                  statusEl.className = "status-indicator error";
                }
                resetCaptchaWidget();
              });
            };

            window.onCaptchaExpired = function() {
              window.__ptSubmitting = false;
              var statusEl = document.getElementById("status");
              if (statusEl) {
                statusEl.innerText = "Security challenge expired. Please verify again.";
                statusEl.className = "status-indicator error";
              }
            };

            window.onCaptchaError = function(code) {
              window.__ptSubmitting = false;
              var statusEl = document.getElementById("status");
              if (statusEl) {
                statusEl.innerText = "Security challenge error (" + (code || "network") + "). Please reload.";
                statusEl.className = "status-indicator error";
              }
            };
          </script>
          #{script_tag}
          <style #{nonce_attr}>
            :root {
              --primary: #222222;
              --secondary: #ffffff;
              --tertiary: #0088cc;
              --tertiary-hover: #006699;
              --primary-low: #e9e9e9;
              --primary-very-low: #f8f8f8;
              --primary-medium: #888888;
              --primary-high: #444444;
              --header_background: #ffffff;
              --header_primary: #222222;
              --success: #009900;
              --danger: #e45735;
              --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
              --d-border-radius: 10px;
            }

            @media (prefers-color-scheme: dark) {
              :root {
                --primary: #dddddd;
                --secondary: #111214;
                --tertiary: #38bdf8;
                --tertiary-hover: #0284c7;
                --primary-low: #282a2e;
                --primary-very-low: #1b1c20;
                --primary-medium: #999999;
                --primary-high: #bbbbbb;
                --header_background: #18191c;
                --header_primary: #dddddd;
                --success: #22c55e;
                --danger: #ef4444;
              }
            }

            * {
              box-sizing: border-box;
              margin: 0;
              padding: 0;
            }

            html, body {
              height: 100%;
              background-color: var(--secondary);
              color: var(--primary);
              font-family: var(--font-family);
              font-size: 15px;
              line-height: 1.4;
              -webkit-font-smoothing: antialiased;
            }

            body {
              display: flex;
              flex-direction: column;
            }

            .wrap {
              max-width: 1110px;
              margin-left: auto;
              margin-right: auto;
              padding: 0 10px;
              width: 100%;
            }

            .d-header {
              height: 60px;
              background-color: var(--header_background);
              border-bottom: 1px solid var(--primary-low);
              display: flex;
              align-items: center;
              box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
            }

            .d-header .contents {
              display: flex;
              align-items: center;
              justify-content: space-between;
              width: 100%;
            }

            .d-header .title a {
              display: inline-flex;
              align-items: center;
              gap: 0.5rem;
              text-decoration: none;
              color: var(--header_primary);
            }

            .d-header .logo-big {
              max-height: 40px;
              width: auto;
              object-fit: contain;
            }

            .d-header .d-icon-discourse {
              width: 32px;
              height: 32px;
              color: var(--tertiary);
            }

            .d-header #site-text-logo {
              font-size: 1.35rem;
              font-weight: 700;
              letter-spacing: -0.02em;
              color: var(--header_primary);
            }

            #main {
              flex: 1 0 auto;
              display: flex;
              flex-direction: column;
            }

            #main-outlet {
              flex: 1 0 auto;
              padding-top: 3.5rem;
              padding-bottom: 3.5rem;
              display: flex;
              align-items: center;
              justify-content: center;
            }

            #simple-container {
              width: 100%;
              max-width: 520px;
              margin: 0 auto;
            }

            .checkpoint-panel {
              background: var(--secondary);
              border: 1px solid var(--primary-low);
              border-radius: var(--d-border-radius);
              box-shadow: 0 4px 20px rgba(0, 0, 0, 0.06);
              padding: 2.5rem 2.25rem 2rem;
              text-align: center;
            }

            .brand-badge {
              display: inline-flex;
              align-items: center;
              gap: 0.4rem;
              background-color: var(--primary-very-low);
              border: 1px solid var(--primary-low);
              color: var(--primary-high);
              padding: 0.35rem 0.85rem;
              border-radius: 50px;
              font-size: 0.8125rem;
              font-weight: 600;
              margin-bottom: 1.5rem;
              letter-spacing: 0.02em;
            }

            .brand-badge svg {
              width: 16px;
              height: 16px;
              color: var(--tertiary);
            }

            .brand-badge strong {
              color: var(--tertiary);
              font-weight: 700;
            }

            .checkpoint-panel h1 {
              font-size: 1.45rem;
              font-weight: 700;
              margin-bottom: 0.75rem;
              color: var(--primary);
            }

            .checkpoint-panel p.instructions {
              font-size: 0.95rem;
              color: var(--primary-medium);
              line-height: 1.55;
              margin-bottom: 1.5rem;
            }

            .widget-box {
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 75px;
              margin: 1.5rem 0;
            }

            .status-indicator {
              font-size: 0.875rem;
              min-height: 22px;
              margin-top: 0.5rem;
              color: var(--primary-medium);
              transition: color 0.2s ease;
            }

            .status-indicator.success {
              color: var(--success);
              font-weight: 600;
            }

            .status-indicator.error {
              color: var(--danger);
              font-weight: 600;
            }

            .alert {
              padding: 0.75rem 1rem;
              border-radius: var(--d-border-radius);
              font-size: 0.875rem;
              margin-bottom: 1.25rem;
              text-align: left;
            }

            .alert-error {
              background-color: rgba(228, 87, 53, 0.1);
              border: 1px solid var(--danger);
              color: var(--danger);
            }

            #footer {
              flex-shrink: 0;
              padding: 1.5rem 0;
              border-top: 1px solid var(--primary-low);
              text-align: center;
              font-size: 0.8125rem;
              color: var(--primary-medium);
            }

            #footer a {
              color: var(--primary-high);
              text-decoration: none;
              font-weight: 600;
            }

            #footer a:hover {
              color: var(--tertiary);
            }
          </style>
        </head>
        <body>
          <section id="main">
            <header class="d-header">
              <div class="wrap">
                <div class="contents">
                  <div class="title">
                    <a href="/">
                      #{logo_html}
                    </a>
                  </div>
                </div>
              </div>
            </header>

            <div id="main-outlet" class="wrap">
              <div id="simple-container">
                <div class="checkpoint-panel">
                  #{brand_badge_html}
                  <h1>Security Verification</h1>
                  <p class="instructions">A proxy or VPN connection was detected. Please complete the quick security check below to verify your connection and continue to <b>#{site_name}</b>.</p>

                  #{missing_key_warning}

                  <div class="widget-box">
                    #{if is_hcaptcha
                      "<div class=\"h-captcha\" id=\"captcha-widget\" data-sitekey=\"#{escaped_site_key}\" data-callback=\"onCaptchaSuccess\" data-expired-callback=\"onCaptchaExpired\" data-error-callback=\"onCaptchaError\"></div>"
                    else
                      "<div class=\"cf-turnstile\" id=\"captcha-widget\" data-sitekey=\"#{escaped_site_key}\" data-callback=\"onCaptchaSuccess\" data-expired-callback=\"onCaptchaExpired\" data-error-callback=\"onCaptchaError\"></div>"
                    end}
                  </div>

                  <div id="status" class="status-indicator">Please complete the challenge above to proceed.</div>
                </div>
              </div>
            </div>
          </section>

          #{footer_html}

          <script #{nonce_attr}>
            window.addEventListener("load", function() {
              setTimeout(function() {
                var widgetEl = document.getElementById("captcha-widget");
                if (widgetEl && widgetEl.children.length === 0) {
                  if (typeof hcaptcha !== "undefined") {
                    try {
                      hcaptcha.render("captcha-widget", {
                        sitekey: window.__ptSiteKey,
                        callback: window.onCaptchaSuccess,
                        "expired-callback": window.onCaptchaExpired,
                        "error-callback": window.onCaptchaError
                      });
                    } catch (e) {
                      console.warn("hCaptcha manual render error:", e);
                    }
                  } else if (typeof turnstile !== "undefined") {
                    try {
                      turnstile.render("#captcha-widget", {
                        sitekey: window.__ptSiteKey,
                        callback: window.onCaptchaSuccess,
                        "expired-callback": window.onCaptchaExpired,
                        "error-callback": window.onCaptchaError
                      });
                    } catch (e) {
                      console.warn("Turnstile manual render error:", e);
                    }
                  }
                }
              }, 400);
            });
          </script>
        </body>
        </html>
      HTML
    end
  end
end
