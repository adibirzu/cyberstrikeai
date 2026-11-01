# Pentforge Access identity bridge

The hosted deployment exchanges a verified Cloudflare Access application assertion for an existing CyberStrikeAI RBAC session. The browser attempts this before rendering the sign-in overlay, so an authorised Access session opens the app directly.

The issuer and key location are fixed to the Pentforge team domain. RS256 signature, issuer, application audience, expiry, not-before, email and subject are checked using coreos/go-oidc. An optional forwarded email header must match the signed identity. Token-controlled URLs are never fetched. Failed verification returns401; an unmapped or disabled native account returns403. The response is not cached.

Runtime names (values belong outside Git):

- `CYBERSTRIKE_ACCESS_AUD`: this application's64-character Access audience.
- `CYBERSTRIKE_ACCESS_USER_MAP`: JSON mapping exact verified emails to existing local usernames. Unmapped identities are looked up by their complete email address. Never infer a local username from the email prefix.
- `CYBERSTRIKE_ACCESS_SSO_ONLY=true`: retires the password login route with410 and hides its form on the hosted deployment.

No account or role is auto-created by the bridge. The existing database remains authoritative for enabled state, roles, permissions and resource scope. Access authentication is not an assessment authorisation. Corporate email-code identities can use the same bridge when their Access policy and exact native account grant permit it; the bridge does not depend on Google-specific claims.

Tests cover real signed fixture assertions, forged signatures, unsigned tokens, issuer/audience/expiry/not-before failures, email/header mismatch, disabled users, explicit owner mapping, cross-domain email-prefix collision, existing corporate viewer rights and retired password entry. Fixtures use the two owner-requested corporate test addresses; passing fixture tests does not establish a completed live mailbox login.

Preserve loopback-only origin binding and tunnel JWT validation. Deploy a committed source revision, back up the current binary outside the web root, verify no assessment is active, replace atomically and restart only this service. Native sessions are in memory and a restart requires the browser to exchange its Access identity again. Keep customer data and runtime mapping/secrets out of the repository.
