import { OAuth2Strategy } from "remix-auth-oauth2";
import type { Strategy } from "remix-auth/strategy";
import jwt from "jsonwebtoken";

import type {
  OktaProfile,
  OktaStrategyOptions,
  OktaUserInfo,
} from "./types.js";
export * from "./types.js";

export class OktaStrategy<User> extends OAuth2Strategy<User> {
  public override name = "okta";

  private static userInfoPath = `/oauth2/default/v1/userinfo`;

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
        cookie: {
          name: "okta-oauth2",
        },
        clientId,
        clientSecret,
        redirectURI,
        authorizationEndpoint: `${oktaDomain}/oauth2/default/v1/authorize`,
        tokenEndpoint: `${oktaDomain}/oauth2/default/v1/token`,
        scopes,
      },
      verify
    );
  }

  protected override authorizationParams(
    params: URLSearchParams
  ): URLSearchParams {
    // pass through on existing params allows for e.g. state to flow through
    const extendedParams = new URLSearchParams(params);
    extendedParams.set("client_id", this.client.clientId);
    if (this.options.redirectURI) {
      extendedParams.set("redirect_uri", this.options.redirectURI.toString());
    }
    if (this.options.scopes) {
      extendedParams.set("scope", this.options.scopes.join(" "));
    }
    extendedParams.set("response_type", "code");
    return extendedParams;
  }

  public static async userProfile(accessToken: string): Promise<OktaProfile> {
    const { iss } = jwt.decode(accessToken) as { iss: string };
    const userInfoEndpoint = `${new URL(iss).origin}${
      OktaStrategy.userInfoPath
    }`;
    const response = await fetch(userInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    const profile: OktaUserInfo = await response.json();
    return {
      provider: "okta",
      id: profile.sub,
      ...profile,
    };
  }
}
