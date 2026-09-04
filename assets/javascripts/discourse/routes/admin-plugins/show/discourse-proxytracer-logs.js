import DiscourseRoute from "discourse/routes/discourse";

export default class AdminPluginsShowDiscourseProxyTracerLogsRoute extends DiscourseRoute {
  setupController(controller, model) {
    super.setupController(controller, model);
    controller.fetchLogs();
  }
}
