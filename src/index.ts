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

  constructor(
    {
      oktaDomain,
      oktaServerName,
      clientId,
      clientSecret,
      redirectURI,
      scopes = ["openid", "profile", "email"],
    }: OktaStrategyOptions,
    verify: Strategy.VerifyFunction<User, OAuth2Strategy.VerifyOptions>
  ) {
    const endpointBase = oktaServerName
      ? `${oktaDomain}/oauth2/${oktaServerName}/v1`
      : `${oktaDomain}/oauth2/v1`;

    super(
      {
        cookie: {
          name: "okta-oauth2",
        },
        clientId,
        clientSecret,
        redirectURI,
        authorizationEndpoint: `${endpointBase}/authorize`,
        tokenEndpoint: `${endpointBase}/token`,
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

  public static async userProfile(
    accessToken: string,
    opts?: { oktaServerName?: string }
  ): Promise<OktaProfile> {
    const claims = jwt.decode(accessToken) as { iss: string };
    const userInfoPath = `/oauth2/${
      opts?.oktaServerName ? `${opts.oktaServerName}/` : ""
    }v1/userinfo`;
    const userInfoEndpoint = `${new URL(claims.iss).origin}${userInfoPath}`;
    console.log("userInfoEndpoint", userInfoEndpoint);
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
