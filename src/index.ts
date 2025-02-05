import { OAuth2Strategy } from "remix-auth-oauth2";
import type { Strategy } from "remix-auth/strategy";

import type {
  OktaProfile,
  OktaStrategyOptions,
  OktaUserInfo,
} from "./types.js";
export * from "./types.js";

export class OktaStrategy<User> extends OAuth2Strategy<User> {
  public override name = "okta";

  private userInfoURL: string;
  private readonly scopes: string[];
  private sessionToken = "";

  constructor(
    {
      oktaDomain,
      clientId,
      clientSecret,
      redirectURI,
      scopes = ["openid", "profile", "email"],
    }: OktaStrategyOptions,
    verify: Strategy.VerifyFunction<User, OAuth2Strategy.VerifyOptions>
  ) {
    super(
      {
        clientId,
        clientSecret,
        redirectURI,
        authorizationEndpoint: `${oktaDomain}/oauth2/default/v1/authorize`,
        tokenEndpoint: `${oktaDomain}/oauth2/default/v1/token`,
        scopes,
      },
      verify
    );

    this.scopes = scopes;
    this.userInfoURL = `${oktaDomain}/oauth2/default/v1/userinfo`;
    // `${oktaDomain}/oauth2/default/api/v1/authn`;
  }

  protected override authorizationParams() {
    return new URLSearchParams({
      scope: this.scopes.join(" "),
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
