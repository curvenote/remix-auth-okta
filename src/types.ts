import type { OAuth2StrategyOptions } from "remix-auth-oauth2";

export interface OktaProfile {
  provider: string;
  id: string;
  displayName: string;
  name: {
    familyName: string;
    givenName: string;
    middleName: string;
  };
  email: string;
}

export type OktaUserInfo = {
  sub: string;
  name: string;
  preferred_username: string;
  nickname: string;
  given_name: string;
  middle_name: string;
  family_name: string;
  profile: string;
  zoneinfo: string;
  locale: string;
  updated_at: string;
  email: string;
  email_verified: boolean;
};

export type OktaStrategyOptions = Omit<
  OAuth2StrategyOptions,
  "authorizationURL" | "tokenURL"
> & {
  oktaDomain: string;
  scope?: string;
  issuer?: string;
  debug?: boolean;
} & { withCustomLoginForm?: boolean };

export type OktaExtraParams = Record<string, string | number>;
