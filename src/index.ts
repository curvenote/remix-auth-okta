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
    verify: Strategy.VerifyFunction<User, OAuth2Strategy.VerifyOptions>,
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
      verify,
    );
  }

  protected override authorizationParams(
    parameters: URLSearchParams,
  ): URLSearchParams {
    // pass through on existing params allows for e.g. state to flow through
    const extendedParameters = new URLSearchParams(parameters);
    extendedParameters.set("client_id", this.client.clientId);
    if (this.options.redirectURI) {
      extendedParameters.set(
        "redirect_uri",
        this.options.redirectURI.toString(),
      );
    }
    if (this.options.scopes) {
      extendedParameters.set("scope", this.options.scopes.join(" "));
    }
    extendedParameters.set("response_type", "code");
    return extendedParameters;
  }

  public static async userProfile(
    accessToken: string,
    options?: { oktaServerName?: string },
  ): Promise<OktaProfile> {
    const claims = jwt.decode(accessToken) as { iss: string };
    const userInfoPath = `/oauth2/${
      options?.oktaServerName ? `${options.oktaServerName}/` : ""
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
