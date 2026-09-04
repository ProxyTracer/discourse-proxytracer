import { LinkTo } from "@ember/routing";
import DBreadcrumbsItem from "discourse/components/d-breadcrumbs-item";
import DPageSubheader from "discourse/components/d-page-subheader";
import ConditionalLoadingSpinner from "discourse/components/conditional-loading-spinner";
import { i18n } from "discourse-i18n";

export default <template>
  <DBreadcrumbsItem
    @path="/admin/plugins/discourse-proxytracer/logs"
    @label={{i18n "proxytracer.admin.logs.title"}}
  />

  <div class="proxytracer-admin-logs admin-detail">
    <DPageSubheader
      @titleLabel={{i18n "proxytracer.admin.logs.title"}}
    />

    <ConditionalLoadingSpinner @condition={{@controller.loading}}>
      {{#if @controller.error}}
        <div class="alert alert-error">
          <strong>Error loading logs:</strong> {{@controller.error}}
        </div>
      {{/if}}

      {{#if @controller.logs.length}}
        <table class="table grid">
          <thead>
            <tr>
              <th>{{i18n "proxytracer.admin.logs.timestamp"}}</th>
              <th>{{i18n "proxytracer.admin.logs.ip"}}</th>
              <th>{{i18n "proxytracer.admin.logs.username"}}</th>
              <th>{{i18n "proxytracer.admin.logs.action"}}</th>
            </tr>
          </thead>
          <tbody>
            {{#each @controller.logs as |log|}}
              <tr>
                <td>{{log.timestamp}}</td>
                <td><code>{{log.ip}}</code></td>
                <td>
                  {{#if log.username}}
                    <LinkTo @route="user" @model={{log.username}}>
                      {{log.username}}
                    </LinkTo>
                  {{else}}
                    <span class="text-muted">—</span>
                  {{/if}}
                </td>
                <td>
                  <span class="badge">{{log.action}}</span>
                </td>
              </tr>
            {{/each}}
          </tbody>
        </table>
      {{else}}
        <div class="alert alert-info">
          {{i18n "proxytracer.admin.logs.empty"}}
        </div>
      {{/if}}
    </ConditionalLoadingSpinner>
  </div>
</template>
