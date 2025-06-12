# @curvenote/remix-auth-okta

## 3.0.0

### Major Changes

- 8472d31: Added `oktaServerName` argument allowing the namee of a custom authenication server to be set. This changes the previous behaviour where the `default` custom server would always be targeted, now the organisation server will be targetted by default.

## 2.0.0

### Major Changes

- cdb86aa: \* Upgraded to use `remix-auth@4`
  - Removed form based login support
  - Renamed package and publishing under `@curvenote/remix-auth-okta`
