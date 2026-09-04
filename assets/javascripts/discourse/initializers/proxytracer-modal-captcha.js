import { withPluginApi } from "discourse/lib/plugin-api";
import { ajax } from "discourse/lib/ajax";
import loadScript from "discourse/lib/load-script";

const HCAPTCHA_SCRIPT_URL = "https://hcaptcha.com/1/api.js?render=explicit";
const TURNSTILE_SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

const vpnStatusCache = new Map();
const VPN_CACHE_TTL = 30000;

async function checkVpnRequired(siteSettings, context = "auth") {
  const action = (
    siteSettings.ProxyTracer_Action ||
    siteSettings.proxytracer_action ||
    siteSettings.proxy_tracer_action ||
    ""
  ).toLowerCase();

  const siteKey = (
    siteSettings.ProxyTracer_Captcha_Site_Key ||
    siteSettings.proxytracer_captcha_site_key ||
    siteSettings.proxy_tracer_captcha_site_key ||
    ""
  );

  const enabled = siteSettings.proxytracer_enabled !== false;

  if (!enabled || action !== "captcha" || !siteKey) {
    return false;
  }

  const now = Date.now();
  const cached = vpnStatusCache.get(context);
  if (cached && (now - cached.time) < VPN_CACHE_TTL) {
    return cached.required;
  }

  try {
    const res = await ajax(`/proxytracer/check-status?context=${encodeURIComponent(context)}`);
    const required = Boolean(res?.required);
    vpnStatusCache.set(context, { required, time: now });
    return required;
  } catch (e) {
    return false;
  }
}

async function fetchFreshChallenge(context = "auth") {
  try {
    const res = await ajax(`/proxytracer/check-status?context=${encodeURIComponent(context)}`);
    return res?.challenge_id || null;
  } catch (e) {
    return null;
  }
}

async function renderModalCaptcha(modalBody, siteSettings) {
  if (modalBody.querySelector("#pt-forgot-password-captcha")) {
    return;
  }

  const challengeId = await fetchFreshChallenge("forgot_password");
  if (!challengeId || !modalBody.isConnected) {
    return;
  }

  const provider = (
    siteSettings.ProxyTracer_Captcha_Provider ||
    siteSettings.proxytracer_captcha_provider ||
    siteSettings.proxy_tracer_captcha_provider ||
    "turnstile"
  ).toLowerCase();

  const siteKey = (
    siteSettings.ProxyTracer_Captcha_Site_Key ||
    siteSettings.proxytracer_captcha_site_key ||
    siteSettings.proxy_tracer_captcha_site_key ||
    ""
  );

  const wrapper = document.createElement("div");
  wrapper.id = "pt-forgot-password-captcha";
  wrapper.className = "proxytracer-captcha-wrapper";
  wrapper.style.cssText = "margin-top: 1rem; text-align: center;";

  const container = document.createElement("div");
  container.id = "pt-forgot-password-widget-" + Math.random().toString(36).substring(2, 9);
  container.className = "proxytracer-captcha-container";
  container.style.cssText = "display: flex; justify-content: center; min-height: 65px;";

  const statusDiv = document.createElement("div");
  statusDiv.className = "proxytracer-status-msg";
  statusDiv.style.cssText = "font-size: 0.875rem; margin-top: 0.25rem;";

  wrapper.appendChild(container);
  wrapper.appendChild(statusDiv);

  const showBranding = (
    siteSettings.ProxyTracer_Show_Branding !== false &&
    siteSettings.proxytracer_show_branding !== false
  );

  if (showBranding) {
    const brandDiv = document.createElement("div");
    brandDiv.className = "proxytracer-branding-note";
    brandDiv.style.cssText = "font-size: 0.75rem; color: var(--primary-medium); margin-top: 0.35rem; display: flex; align-items: center; justify-content: center; gap: 0.3rem;";
    brandDiv.innerHTML = `
      <svg style="width: 12px; height: 12px; color: var(--tertiary);" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
      </svg>
      <span>Protected by <a href="https://proxytracer.com" target="_blank" rel="noopener noreferrer" style="color: var(--tertiary); font-weight: 600; text-decoration: none;">ProxyTracer</a></span>
    `;
    wrapper.appendChild(brandDiv);
  }

  modalBody.appendChild(wrapper);

  const scriptUrl = provider === "hcaptcha" ? HCAPTCHA_SCRIPT_URL : TURNSTILE_SCRIPT_URL;
  let widgetId = null;
  let activeChallengeId = challengeId;

  const resetWidget = async () => {
    try {
      const freshId = await fetchFreshChallenge("forgot_password");
      if (freshId) activeChallengeId = freshId;
      if (provider === "hcaptcha" && window.hcaptcha && widgetId !== null) {
        window.hcaptcha.reset(widgetId);
      } else if (provider === "turnstile" && window.turnstile && widgetId !== null) {
        window.turnstile.reset(widgetId);
      }
    } catch (e) {}
  };

  loadScript(scriptUrl)
    .then(() => {
      const handleVerify = async (token) => {
        if (!token) return;
        statusDiv.style.color = "var(--primary-medium)";
        statusDiv.textContent = "Verifying security token...";
        try {
          const resp = await ajax("/proxytracer/verify-captcha", {
            type: "POST",
            data: { token, challenge_id: activeChallengeId },
          });
          if (resp?.success) {
            statusDiv.style.color = "var(--success, #22c55e)";
            statusDiv.textContent = "✓ Security check verified";
            vpnStatusCache.set("forgot_password", { required: false, time: Date.now() });
          } else {
            statusDiv.style.color = "var(--danger, #ef4444)";
            statusDiv.textContent = resp?.error || "Verification failed. Please try again.";
            await resetWidget();
          }
        } catch (err) {
          statusDiv.style.color = "var(--danger, #ef4444)";
          statusDiv.textContent = err?.jqXHR?.responseJSON?.error || "Verification failed.";
          await resetWidget();
        }
      };

      const renderWithRetry = (attempts = 0) => {
        const target = document.getElementById(container.id) || container;
        if (!target || !target.isConnected) {
          if (attempts < 30) setTimeout(() => renderWithRetry(attempts + 1), 100);
          return;
        }

        try {
          if (provider === "hcaptcha" && window.hcaptcha && typeof window.hcaptcha.render === "function") {
            widgetId = window.hcaptcha.render(target, {
              sitekey: siteKey,
              callback: handleVerify,
              "expired-callback": resetWidget,
              "error-callback": resetWidget,
            });
            return;
          } else if (provider === "turnstile" && window.turnstile && typeof window.turnstile.render === "function") {
            widgetId = window.turnstile.render(target, {
              sitekey: siteKey,
              callback: handleVerify,
              "expired-callback": resetWidget,
              "error-callback": resetWidget,
            });
            return;
          }
        } catch (e) {
          console.error("[ProxyTracer] Error rendering modal CAPTCHA:", e);
        }

        if (attempts < 30) {
          setTimeout(() => renderWithRetry(attempts + 1), 100);
        }
      };

      renderWithRetry();
    })
    .catch((err) => {
      console.error("[ProxyTracer] Failed to load CAPTCHA script:", err);
      statusDiv.style.color = "var(--danger, #ef4444)";
      statusDiv.textContent = "Failed to load security verification. Please refresh.";
    });
}

function setupEmailLoginHandler(emailLink, siteSettings) {
  if (emailLink.dataset.ptAttached) return;
  emailLink.dataset.ptAttached = "true";

  emailLink.addEventListener("click", async (e) => {
    // Crucial: Halt event propagation synchronously before any async operations,
    // preventing Ember's local-login-form emailLogin handler from running concurrently
    // and popping up a premature "Security verification required" dialog.
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    const loginInput = document.getElementById("login-account-name");
    const loginName = loginInput ? loginInput.value.trim() : "";

    const required = await checkVpnRequired(siteSettings, "email_login");
    if (!required) {
      if (!loginName) {
        const existingMsg = document.getElementById("pt-email-login-status");
        if (existingMsg) existingMsg.remove();
        const errorMsg = document.createElement("div");
        errorMsg.id = "pt-email-login-status";
        errorMsg.style.cssText = "color: var(--danger, #ef4444); font-size: 0.875rem; margin-top: 0.5rem; text-align: center; font-weight: 500;";
        errorMsg.textContent = "Please enter your username or email address.";
        emailLink.parentNode.insertBefore(errorMsg, emailLink.nextSibling);
        return;
      }

      try {
        const currentLoginName = loginInput ? loginInput.value.trim() : loginName;
        await ajax("/u/email-login", {
          data: { login: currentLoginName },
          type: "POST",
        });
        const existingMsg = document.getElementById("pt-email-login-status");
        if (existingMsg) existingMsg.remove();

        const successMsg = document.createElement("div");
        successMsg.id = "pt-email-login-status";
        successMsg.style.cssText = "color: var(--success, #22c55e); font-size: 0.875rem; margin-top: 0.5rem; text-align: center; font-weight: 500;";
        successMsg.textContent = "✓ Login link sent! Check your email.";
        emailLink.parentNode.insertBefore(successMsg, emailLink.nextSibling);
      } catch (err) {
        const errorMsg = err?.jqXHR?.responseJSON?.errors?.[0] || err?.jqXHR?.responseJSON?.error || "Failed to send login link.";
        const existingMsg = document.getElementById("pt-email-login-status");
        if (existingMsg) existingMsg.remove();

        const errDiv = document.createElement("div");
        errDiv.id = "pt-email-login-status";
        errDiv.style.cssText = "color: var(--danger, #ef4444); font-size: 0.875rem; margin-top: 0.5rem; text-align: center;";
        errDiv.textContent = errorMsg;
        emailLink.parentNode.insertBefore(errDiv, emailLink.nextSibling);
      }
      return;
    }

    // VPN is required -> intercept and render dedicated CAPTCHA box
    let box = document.getElementById("pt-email-login-box");
    if (!box) {
      const challengeId = await fetchFreshChallenge("email_login");
      if (!challengeId) return;

      box = document.createElement("div");
      box.id = "pt-email-login-box";
      box.className = "proxytracer-captcha-wrapper";
      box.style.cssText = "margin: 0.75rem 0; padding: 0.75rem; background: var(--primary-very-low); border-radius: 6px; text-align: center;";

      const infoText = document.createElement("p");
      infoText.style.cssText = "font-size: 0.85rem; margin-bottom: 0.5rem; color: var(--primary);";
      infoText.textContent = "🛡️ Complete the security check to send your login link:";

      const container = document.createElement("div");
      container.id = "pt-email-login-widget-" + Math.random().toString(36).substring(2, 9);
      container.style.cssText = "display: flex; justify-content: center; min-height: 65px;";

      const statusDiv = document.createElement("div");
      statusDiv.className = "proxytracer-status-msg";
      statusDiv.style.cssText = "font-size: 0.875rem; margin-top: 0.4rem;";

      box.appendChild(infoText);
      box.appendChild(container);
      box.appendChild(statusDiv);

      const showBranding = (
        siteSettings.ProxyTracer_Show_Branding !== false &&
        siteSettings.proxytracer_show_branding !== false
      );

      if (showBranding) {
        const brandDiv = document.createElement("div");
        brandDiv.className = "proxytracer-branding-note";
        brandDiv.style.cssText = "font-size: 0.75rem; color: var(--primary-medium); margin-top: 0.35rem; display: flex; align-items: center; justify-content: center; gap: 0.3rem;";
        brandDiv.innerHTML = `
          <svg style="width: 12px; height: 12px; color: var(--tertiary);" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
          </svg>
          <span>Protected by <a href="https://proxytracer.com" target="_blank" rel="noopener noreferrer" style="color: var(--tertiary); font-weight: 600; text-decoration: none;">ProxyTracer</a></span>
        `;
        box.appendChild(brandDiv);
      }

      emailLink.parentNode.insertBefore(box, emailLink.nextSibling);

      const provider = (
        siteSettings.ProxyTracer_Captcha_Provider ||
        siteSettings.proxytracer_captcha_provider ||
        siteSettings.proxy_tracer_captcha_provider ||
        "turnstile"
      ).toLowerCase();

      const siteKey = (
        siteSettings.ProxyTracer_Captcha_Site_Key ||
        siteSettings.proxytracer_captcha_site_key ||
        siteSettings.proxy_tracer_captcha_site_key ||
        ""
      );

      const scriptUrl = provider === "hcaptcha" ? HCAPTCHA_SCRIPT_URL : TURNSTILE_SCRIPT_URL;
      let emailWidgetId = null;
      let activeEmailChallengeId = challengeId;

      const resetEmailWidget = async () => {
        try {
          const freshId = await fetchFreshChallenge("email_login");
          if (freshId) activeEmailChallengeId = freshId;
          if (provider === "hcaptcha" && window.hcaptcha && emailWidgetId !== null) {
            window.hcaptcha.reset(emailWidgetId);
          } else if (provider === "turnstile" && window.turnstile && emailWidgetId !== null) {
            window.turnstile.reset(emailWidgetId);
          }
        } catch (e) {}
      };

      loadScript(scriptUrl)
        .then(() => {
          const handleVerify = async (token) => {
            if (!token) return;
            statusDiv.style.color = "var(--primary-medium)";
            statusDiv.textContent = "Verifying security token...";
            try {
              const resp = await ajax("/proxytracer/verify-captcha", {
                type: "POST",
                data: { token, challenge_id: activeEmailChallengeId },
              });
              if (resp?.success) {
                statusDiv.style.color = "var(--success, #22c55e)";
                statusDiv.textContent = "✓ Verified! Sending login link...";
                vpnStatusCache.set("email_login", { required: false, time: Date.now() });
                try {
                  const input = document.getElementById("login-account-name");
                  const currentLogin = (input ? input.value.trim() : "") || loginName;
                  if (!currentLogin) {
                    statusDiv.style.color = "var(--danger, #ef4444)";
                    statusDiv.textContent = "Please enter your username or email address above.";
                    return;
                  }

                  await ajax("/u/email-login", {
                    data: { login: currentLogin },
                    type: "POST",
                  });
                  const successContainer = document.createElement("div");
                  successContainer.style.cssText = "color: var(--success, #22c55e); font-size: 0.9rem; padding: 0.5rem; font-weight: 500;";
                  successContainer.textContent = "✓ Login link sent to ";
                  const boldEl = document.createElement("b");
                  boldEl.textContent = currentLogin;
                  successContainer.appendChild(boldEl);
                  successContainer.appendChild(document.createTextNode("! Check your email."));
                  box.replaceChildren(successContainer);
                } catch (err) {
                  statusDiv.style.color = "var(--danger, #ef4444)";
                  statusDiv.textContent = err?.jqXHR?.responseJSON?.errors?.[0] || err?.jqXHR?.responseJSON?.error || "Failed to send login link.";
                  await resetEmailWidget();
                }
              } else {
                statusDiv.style.color = "var(--danger, #ef4444)";
                statusDiv.textContent = resp?.error || "Verification failed.";
                await resetEmailWidget();
              }
            } catch (err) {
              statusDiv.style.color = "var(--danger, #ef4444)";
              statusDiv.textContent = err?.jqXHR?.responseJSON?.error || "Verification failed.";
              await resetEmailWidget();
            }
          };

          const renderWithRetry = (attempts = 0) => {
            const target = document.getElementById(container.id) || container;
            if (!target || !target.isConnected) {
              if (attempts < 30) setTimeout(() => renderWithRetry(attempts + 1), 100);
              return;
            }

            try {
              if (provider === "hcaptcha" && window.hcaptcha && typeof window.hcaptcha.render === "function") {
                emailWidgetId = window.hcaptcha.render(target, {
                  sitekey: siteKey,
                  callback: handleVerify,
                  "expired-callback": resetEmailWidget,
                  "error-callback": resetEmailWidget,
                });
                return;
              } else if (provider === "turnstile" && window.turnstile && typeof window.turnstile.render === "function") {
                emailWidgetId = window.turnstile.render(target, {
                  sitekey: siteKey,
                  callback: handleVerify,
                  "expired-callback": resetEmailWidget,
                  "error-callback": resetEmailWidget,
                });
                return;
              }
            } catch (e) {
              console.error("[ProxyTracer] Error rendering email-login CAPTCHA:", e);
            }

            if (attempts < 30) {
              setTimeout(() => renderWithRetry(attempts + 1), 100);
            } else {
              statusDiv.style.color = "var(--danger, #ef4444)";
              statusDiv.textContent = "Failed to load security verification. Please refresh.";
            }
          };

          renderWithRetry();
        })
        .catch((err) => {
          console.error("[ProxyTracer] Failed to load CAPTCHA script:", err);
          statusDiv.style.color = "var(--danger, #ef4444)";
          statusDiv.textContent = "Failed to load security verification. Please refresh.";
        });
    } else {
      box.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, true);
}

export default {
  name: "proxytracer-modal-captcha",

  initialize(container) {
    withPluginApi("1.34.0", (api) => {
      const siteSettings = api.container.lookup("service:site-settings");
      if (siteSettings.proxytracer_enabled === false) {
        return;
      }

      let scheduled = false;
      const inspectModals = () => {
        const modalContainer = document.querySelector(".modal-container") || document.getElementById("discourse-modal") || document.body;
        const modalBody = modalContainer.querySelector(".forgot-password-modal .d-modal__body");

        if (modalBody && !modalBody.dataset.ptProcessing && !modalBody.querySelector("#pt-forgot-password-captcha")) {
          modalBody.dataset.ptProcessing = "true";
          checkVpnRequired(siteSettings, "forgot_password").then((required) => {
            if (required && modalBody.isConnected) {
              renderModalCaptcha(modalBody, siteSettings);
            }
          });
        }

        // Email login link can be on the standalone /login page (#main-outlet) OR inside a modal (.modal-container)
        const emailLink = document.getElementById("email-login-link");
        if (emailLink && !emailLink.dataset.ptAttached) {
          setupEmailLoginHandler(emailLink, siteSettings);
        }
      };

      const observer = new MutationObserver(() => {
        if (scheduled) return;
        scheduled = true;
        requestAnimationFrame(() => {
          scheduled = false;
          inspectModals();
        });
      });

      if (window.__proxytracerObserver) {
        try {
          window.__proxytracerObserver.disconnect();
        } catch (e) {}
      }
      window.__proxytracerObserver = observer;
      observer.observe(document.body, { childList: true, subtree: true });

      // Run inspection immediately
      inspectModals();
    });
  },
};
