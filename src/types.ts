import type { OAuth2Strategy } from "remix-auth-oauth2";

export type OktaIdTokenClaims = {
  alg: string;
  kid: string;
  amr: string[];
  aud: string;
  auth_time: number;
  exp: number;
  iat: number;
  idp: string;
  iss: string;
  jti: string;
  sub: string;
  ver: number;
  name?: string;
  nickname?: string;
  preferred_username?: string;
  given_name?: string;
  middle_name?: string;
  family_name?: string;
  profile?: string;
  zoneinfo?: string;
  locale?: string;
  updated_at?: number;
  email?: string;
  email_verified?: boolean;
  address?: { [key: string]: string };
  phone_number?: string;
  groups?: string[];
};

export type OktaProfile = {
  provider: string;
  id: string;
} & OktaUserInfo;

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
  OAuth2Strategy.ConstructorOptions,
  "authorizationEndpoint" | "tokenEndpoint"
> & {
  oktaDomain: string;
  oktaServerName?: string;
  issuer?: string;
  debug?: boolean;
} & { withCustomLoginForm?: boolean };

export type OktaExtraParams = Record<string, string | number>;
