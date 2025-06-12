---
"@curvenote/remix-auth-okta": patch
---

Added `oktaServerName` argument allowing the namee of a custom authenication server to be set. This changes the previous behaviour where the `default` custom server would always be targeted, now the organisation server will be targetted by default.
