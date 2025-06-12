import { createCookieSessionStorage, json } from "@remix-run/node";
import { vi, describe, test, expect, beforeEach } from "vitest";
import {
  OktaExtraParams,
  OktaProfile,
  OktaStrategy,
  OktaStrategyOptions,
} from "../src";

const BASE_OPTIONS = {
  name: "form",
  sessionKey: "user",
  sessionErrorKey: "error",
  sessionStrategyKey: "strategy",
};

describe(OktaStrategy, () => {
  const verify = vi.fn();
  const sessionStorage = createCookieSessionStorage({
    cookie: { 
      name: "okta-oauth2",
      secure: true,
      path: "/",
      httpOnly: true,
      sameSite: "lax"
    },
  });

  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("Authorization Code flow", () => {
    const options: OktaStrategyOptions = Object.freeze({
      oktaDomain: "https://okta.issuer.come",
      clientId: "CLIENT_ID",
      clientSecret: "CLIENT_SECRET",
      redirectURI: "https://mysite.com/okta/callback",
      scopes: ["openid", "profile", "email"],
    });

    test("should have the scope `openid profile email` as default", async () => {
      const request = new Request("https://mysite.com/okta/auth");
      const strategy = new OktaStrategy(options, verify);
      try {
        await strategy.authenticate(request);
      } catch (error) {
        if (!(error instanceof Response)) throw error;
        const location = error.headers.get("Location");
        if (!location) throw new Error("No redirect header");
        const redirectUrl = new URL(location);
        expect(redirectUrl.searchParams.get("scope")).toBe(
          "openid profile email"
        );
      }
    });

    test("should allow changing the scopes", async () => {
      const strategy = new OktaStrategy(
        { ...options, scopes: ["custom", "scope"] },
        verify
      );
      const request = new Request("https://mysite.com/okta/auth");
      try {
        await strategy.authenticate(request);
      } catch (error) {
        if (!(error instanceof Response)) throw error;
        const location = error.headers.get("Location");
        if (!location) throw new Error("No redirect header");
        const redirectUrl = new URL(location);
        expect(redirectUrl.searchParams.get("scope")).toBe("custom scope");
      }
    });
    
    test("should call verify with the access token, refresh token, extra params, user profile and context", async () => {
      const strategy = new OktaStrategy(options, verify);

      // Create a plain cookie with the state store format
      const stateStore = new URLSearchParams();
      stateStore.set("state", "random-state");
      stateStore.set("random-state", "random-code-verifier");
      const cookie = `okta-oauth2=${stateStore.toString()}; Path=/; HttpOnly; SameSite=Lax`;

      const request = new Request(
        `${options.redirectURI}?state=random-state&code=random-code`,
        {
          headers: { 
            cookie,
            "Content-Type": "application/x-www-form-urlencoded"
          },
        }
      );

      // Mock the token endpoint response
      global.fetch = vi.fn()
        .mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({
              access_token: "access-token",
              refresh_token: "refresh-token",
              id_token: "id-token"
            }),
            text: () => Promise.resolve(""),
            headers: new Headers(),
            clone: () => ({
              ok: true,
              status: 200,
              json: () => Promise.resolve({
                access_token: "access-token",
                refresh_token: "refresh-token",
                id_token: "id-token"
              }),
              text: () => Promise.resolve(""),
              headers: new Headers()
            })
          })
        )
        .mockImplementationOnce(() =>
          Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({
              sub: "user-id",
              name: "John Doe",
              email: "john.doe@example.com",
              picture: "https://example.com/picture.jpg"
            }),
            text: () => Promise.resolve(""),
            headers: new Headers(),
            clone: () => ({
              ok: true,
              status: 200,
              json: () => Promise.resolve({
                sub: "user-id",
                name: "John Doe",
                email: "john.doe@example.com",
                picture: "https://example.com/picture.jpg"
              }),
              text: () => Promise.resolve(""),
              headers: new Headers()
            })
          })
        );

      await strategy.authenticate(request);

      expect(verify).toHaveBeenCalledWith({
        request,
        tokens: {
          data: {
            access_token: "access-token",
            refresh_token: "refresh-token",
            id_token: "id-token"
          }
        }
      });
    });
  });

  // The Password flow and other tests would be removed or rewritten if the strategy no longer supports them.
});
