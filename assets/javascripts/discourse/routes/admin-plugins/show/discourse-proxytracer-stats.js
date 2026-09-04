import DiscourseRoute from "discourse/routes/discourse";

export default class AdminPluginsShowDiscourseProxyTracerStatsRoute extends DiscourseRoute {
  setupController(controller, model) {
    super.setupController(controller, model);
    controller.fetchStats();
  }
}
