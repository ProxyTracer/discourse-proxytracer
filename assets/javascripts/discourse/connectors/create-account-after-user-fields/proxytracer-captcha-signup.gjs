/* eslint-disable ember/no-classic-components */
import Component from "@ember/component";
import { tagName } from "@ember-decorators/component";
import ProxyTracerCaptcha from "../../components/proxytracer-captcha";

@tagName("")
export default class ProxyTracerCaptchaSignupConnector extends Component {
  <template>
    <div
      class="create-account-after-user-fields-outlet proxytracer-captcha-signup"
      ...attributes
    >
      <div class="input-group">
        <ProxyTracerCaptcha @context="signup" />
      </div>
    </div>
  </template>
}
