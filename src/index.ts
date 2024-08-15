import type { SessionStorage } from "@remix-run/server-runtime";
import { AuthenticateOptions, StrategyVerifyCallback } from "remix-auth";
import { OAuth2Strategy, OAuth2StrategyVerifyParams } from "remix-auth-oauth2";
import type {
  OktaExtraParams,
  OktaProfile,
  OktaStrategyOptions,
  OktaUserInfo,
} from "./types";
export * from "./types";

export class OktaStrategy<User> extends OAuth2Strategy<
  User,
  OktaProfile,
  OktaExtraParams
> {
  name = "okta";
  private userInfoURL: string;
  private authenticationURL: string;
  private readonly scope: string;
  private readonly issuer: string;
  private readonly debug: boolean;
  private readonly withCustomLoginForm: boolean;
  private sessionToken = "";
  constructor(
    {
      oktaDomain,
      issuer = oktaDomain,
      scope = "openid profile email",
      clientID,
      clientSecret,
      callbackURL,
      debug = false,
      ...rest
    }: OktaStrategyOptions,
    verify: StrategyVerifyCallback<
      User,
      OAuth2StrategyVerifyParams<OktaProfile, OktaExtraParams>
    >
  ) {
    super(
      {
        authorizationURL: `${oktaDomain}/oauth2/default/v1/authorize`,
        tokenURL: `${oktaDomain}/oauth2/default/v1/token`,
        clientID,
        clientSecret,
        callbackURL,
      },
      verify
    );
    this.debug = debug;
    this.issuer = issuer;
    this.scope = scope;
    this.userInfoURL = `${oktaDomain}/oauth2/default/v1/userinfo`;
    this.authenticationURL = `${oktaDomain}/oauth2/default/api/v1/authn`;
    this.withCustomLoginForm = !!rest.withCustomLoginForm;
    this.authenticationURL = rest.withCustomLoginForm
      ? `${oktaDomain}/api/v1/authn`
      : "";
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    if (this.debug) console.debug("Authenticate with OktaStrategy");
    if (!this.withCustomLoginForm) {
      if (this.debug)
        console.debug(
          "No custom login form, using remix-auth-oauth2::authenticate()"
        );
      return super.authenticate(request, sessionStorage, options);
    }

    const session = await sessionStorage.getSession(
      request.headers.get("Cookie")
    );

    let user: User | null = session.get(options.sessionKey) ?? null;
    if (user) {
      return this.success(user, request.clone(), sessionStorage, options);
    }

    const url = new URL(request.url);
    const callbackUrl = this.getCallbackURLFrom(url);
    if (url.pathname !== callbackUrl.pathname) {
      const form = await request.formData();
      const email = form.get("email");
      const password = form.get("password");

      if (!email || !password) {
        throw new Response(
          JSON.stringify({
            message: "Bad request, missing email and password.",
          }),
          {
            headers: {
              "Content-Type": "application/json; charset=utf-8",
            },
            status: 400,
          }
        );
      }
      this.sessionToken = await this.getSessionTokenWith(
        email.toString(),
        password.toString()
      );
    }

    return super.authenticate(request, sessionStorage, options);
  }

  private getCallbackURLFrom(url: URL) {
    if (
      this.callbackURL.startsWith("http:") ||
      this.callbackURL.startsWith("https:")
    ) {
      return new URL(this.callbackURL);
    }
    if (this.callbackURL.startsWith("/")) {
      return new URL(this.callbackURL, url);
    }
    return new URL(`${url.protocol}//${this.callbackURL}`);
  }

  private async getSessionTokenWith(
    email: string,
    password: string
  ): Promise<string> {
    let response = await fetch(this.authenticationURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: email,
        password,
      }),
    });

    if (!response.ok) {
      try {
        let body = await response.text();

        throw new Error(body);
      } catch (error) {
        throw error;
      }
    }
    const data = await response.json();
    return data.sessionToken;
  }

  protected authorizationParams() {
    return new URLSearchParams({
      scope: this.scope,
      sessionToken: this.sessionToken,
    });
  }

  protected async userProfile(accessToken: string): Promise<OktaProfile> {
    const response = await fetch(this.userInfoURL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    const profile: OktaUserInfo = await response.json();
    return {
      provider: "okta",
      id: profile.sub,
      name: {
        familyName: profile.family_name,
        givenName: profile.given_name,
        middleName: profile.middle_name,
      },
      displayName: profile.name ?? profile.preferred_username,
      email: profile.email,
    };
  }
}
