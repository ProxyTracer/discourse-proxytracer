import { tracked } from "@glimmer/tracking";
import Controller from "@ember/controller";
import { action } from "@ember/object";
import { ajax } from "discourse/lib/ajax";

export default class AdminPluginsShowDiscourseProxyTracerLogsController extends Controller {
  @tracked logs = [];
  @tracked loading = true;
  @tracked error = null;



  @action
  async fetchLogs() {
    this.loading = true;
    this.error = null;
    const url = "/admin/plugins/proxytracer/logs";

    try {
      const response = await ajax(url);
      if (response?.error) {
        this.error = `Server error: ${response.error}`;
        this.logs = [];
      } else {
        this.logs = response?.logs || [];
      }
    } catch (err) {
      console.error("[ProxyTracer Debug] Error loading logs:", err);
      const status = err?.jqXHR?.status ?? err?.status ?? "unknown";
      const statusText = err?.jqXHR?.statusText ?? err?.errorThrown ?? "";
      const respError = err?.jqXHR?.responseJSON?.error;
      const respText = err?.jqXHR?.responseText ? err.jqXHR.responseText.slice(0, 300) : "";
      const detail = respError || respText || err?.message || "Failed to load logs";
      this.error = `HTTP ${status} (${statusText}): ${detail}`;
      this.logs = [];
    } finally {
      this.loading = false;
    }
  }
}
