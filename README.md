![CI](https://img.shields.io/github/actions/workflow/status/jrakotoharisoa/remix-auth-okta/main.yml?branch=main&style=flat-square)
![npm](https://img.shields.io/npm/v/remix-auth-okta?style=flat-square)
# OktaStrategy

The Okta strategy is used to authenticate users against an okta account. It extends the OAuth2Strategy.

## Prerequisites
### Create an Okta Web app

Follow the steps on [the Okta documentation](https://developer.okta.com/docs/guides/sign-into-web-app/nodeexpress/main/#understand-the-callback-route) to create Okta web app and get client ID, client secret and issuer

## How to use

#### Create the strategy instance

```typescript
// app/utils/auth.server.ts
import { Authenticator } from "remix-auth";
import { OktaStrategy } from "remix-auth-okta";
import type { OktaProfile } from "remix-auth-okta";

type User = {
  id: string;
  profile: OktaProfile;
}

// Create an instance of the authenticator, pass a generic with what your
// strategies will return and will be stored in the session
export const authenticator = new Authenticator<User>(sessionStorage);

let oktaStrategy = new OktaStrategy<User>(
  {
    // example of issuer: https://dev-1234.okta.com/oauth2/default
    issuer: "YOUR_OKTA_ISSUER", 
    clientId: "YOUR_OKTA_CLIENT_ID",
    clientSecret: "YOUR_OKTA_CLIENT_SECRET",
    redirectURI: "https://your-app-domain.com/auth/okta/callback",
  },
  async ({ tokens }) => {
    const { id_token, access_token } = tokens.data as { id_token: string; access_token: string };
    const idClaims = jwt.decode(id_token) as OktaIdTokenClaims;
    // check idClaims.exp
    const profile = await OktaStrategy.userProfile(access_token);

    // Get/verify the user data
    return User.findOrCreate({ email: profile.email });
  }
);

authenticator.use(oktaStrategy);
```

### Setup your routes

```typescript
// app/routes/login.tsx
export default function Login() {
  return (
    <Form action="/auth/okta" method="post">
      <button>Login with Okta</button>
    </Form>
  );
}
```

```typescript
// app/routes/auth/okta.tsx
import type { ActionFunction, LoaderFunction } from "remix";

import { authenticator } from "~/utils/auth.server";

export let loader: LoaderFunction = () => redirect("/login");

export let action: ActionFunction = ({ request }) => {
  return authenticator.authenticate("okta", request);
};

```

```typescript
// app/routes/auth/okta/callback.tsx
import type { ActionFunction, LoaderFunction } from "remix";

import { authenticator } from "~/utils/auth.server";

export let loader: LoaderFunction = ({ request }) => {
  const user = await authenticator.authenticate('okta', request);
  if (!user) {
    throw redirect('/login');
  }

  const session = await sessionStorage.getSession(request.headers.get('Cookie'));
  session.set('user', user);

  return redirect('/success', {
    headers: { 'Set-Cookie': await sessionStorage.commitSession(session) },
  });
};
```

## Forked

This strategy was originally forked from [jrakotoharisoa/remix-auth-okta](https://github.com/jrakotoharisoa/remix-auth-okta)  but since modified to use the `remix-auth@4.*` and 
trimming back to drop the form based logins.
* [Original MIT license](https://github.com/jrakotoharisoa/remix-auth-okta)
* Forked at [242a1f3](https://github.com/jrakotoharisoa/remix-auth-okta/commit/242a1f37f87da278790f039d7b51c01fcd985e79)