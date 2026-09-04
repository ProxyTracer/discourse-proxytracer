/* eslint-disable ember/no-classic-components */
import Component from "@ember/component";
import { tagName } from "@ember-decorators/component";
import ProxyTracerCaptcha from "../../components/proxytracer-captcha";

@tagName("")
export default class ProxyTracerCaptchaLoginWrapperConnector extends Component {
  <template>
    <div
      class="login-wrapper-outlet proxytracer-captcha-login-wrapper"
      ...attributes
    >
      {{yield}}
      <ProxyTracerCaptcha @context="login" />
    </div>
  </template>
}
