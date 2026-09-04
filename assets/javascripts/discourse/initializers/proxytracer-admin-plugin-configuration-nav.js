import { withPluginApi } from "discourse/lib/plugin-api";
import { configNavForPlugin } from "discourse/lib/admin-plugin-config-nav";

const PLUGIN_IDS = ["discourse-proxytracer", "discourse-proxytracer-blocker"];

export default {
  name: "proxytracer-admin-plugin-configuration-nav",

  initialize(container) {
    const currentUser = container.lookup("service:current-user");
    if (!currentUser?.admin) {
      return;
    }

    withPluginApi("1.34.0", (api) => {
      PLUGIN_IDS.forEach((pluginId) => {
        try {
          api.setAdminPluginIcon(pluginId, "shield-halved");

          api.addAdminPluginConfigurationNav(pluginId, [
            {
              label: "proxytracer.admin.tabs.stats",
              route: "adminPlugins.show.discourse-proxytracer-stats",
            },
            {
              label: "proxytracer.admin.tabs.logs",
              route: "adminPlugins.show.discourse-proxytracer-logs",
            },
          ]);
        } catch (e) {
          console.error(`[ProxyTracer] Error registering Admin Nav for '${pluginId}':`, e);
        }
      });
    });
  },
};
