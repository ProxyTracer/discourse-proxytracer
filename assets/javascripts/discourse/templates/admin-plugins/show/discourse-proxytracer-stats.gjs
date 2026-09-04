import DBreadcrumbsItem from "discourse/components/d-breadcrumbs-item";
import DPageSubheader from "discourse/components/d-page-subheader";
import ConditionalLoadingSpinner from "discourse/components/conditional-loading-spinner";
import { i18n } from "discourse-i18n";
import ProxyTracerChart from "../../../components/proxytracer-chart";

export default <template>
  <DBreadcrumbsItem
    @path="/admin/plugins/discourse-proxytracer/stats"
    @label={{i18n "proxytracer.admin.stats.title"}}
  />

  <div class="proxytracer-admin-stats admin-detail">
    <DPageSubheader
      @titleLabel={{i18n "proxytracer.admin.stats.title"}}
    />

    <ConditionalLoadingSpinner @condition={{@controller.loading}}>
      {{#if @controller.error}}
        <div class="alert alert-error">
          <strong>Error loading statistics:</strong> {{@controller.error}}
        </div>
      {{/if}}

      {{#if @controller.stats.length}}
        <ProxyTracerChart @stats={{@controller.stats}} />
      {{else}}
        <div class="alert alert-info">
          {{i18n "proxytracer.admin.stats.empty"}}
        </div>
      {{/if}}
    </ConditionalLoadingSpinner>
  </div>
</template>
