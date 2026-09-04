export default {
  resource: "admin.adminPlugins.show",
  path: "/plugins",
  map() {
    this.route("discourse-proxytracer-stats", { path: "stats" });
    this.route("discourse-proxytracer-logs", { path: "logs" });
  },
};
