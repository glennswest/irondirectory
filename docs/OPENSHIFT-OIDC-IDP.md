# OpenShift native OIDC identity provider (#15, D7)

Unlike #14's LDAP identity provider (direct bind, no cross-app SSO),
this is `iron-oidc`: a real OAuth2/OpenID Connect authorization server,
so OpenShift's `oauth-server` gets a token-based login and other modern
apps can point at the same issuer for their own SSO.

## Configuration

```yaml
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
    - name: irondirectory-oidc
      mappingMethod: claim
      type: OpenID
      openID:
        clientID: openshift
        clientSecret:
          name: irondirectory-oidc-client-secret
        issuer: https://oidc.g10.lo
        claims:
          preferredUsername: ["preferred_username"]
          name: ["name"]
          email: ["email"]
        extraScopes: ["profile", "email"]
```

`clientSecret` is a `Secret` in the `openshift-config` namespace with a
`clientSecret` key holding the same value configured for this
`clientID` in `iron-oidcd`'s `IRON_OIDC_CLIENTS` (see
`deploy/systemd/iron-oidcd.conf.example`):

```
IRON_OIDC_CLIENTS=openshift|<same secret as the OpenShift Secret>|https://oauth-openshift.apps.<cluster-domain>/oauth2callback/irondirectory-oidc
```

The `redirect_uri` OpenShift's `oauth-server` actually sends is always
`<oauth-server-route>/oauth2callback/<idp-name>` -- it isn't
configurable independently of the identity provider's `name` above, so
`IRON_OIDC_CLIENTS`' `redirect_uri` must match that exact, predictable
URL for the given cluster.

`issuer` must be `iron-oidcd`'s exact `IRON_OIDC_ISSUER` -- OpenShift
fetches `<issuer>/.well-known/openid-configuration` at startup and
treats every URL in it as authoritative, so a mismatch here means
`oauth-server` builds requests against the wrong endpoints entirely
rather than failing loudly at the point of the typo.

## Live verification (#15)

Standing up a full OpenShift cluster to exercise a well-established
upstream OIDC client (the same reasoning as #14's LDAP IdP doc) is
disproportionate to verifying this issue's actual deliverable: a
correct, FIPS-signed OIDC authorization server. Instead, the exact
protocol exchange `oauth-server` performs was reproduced directly
against a real `iron-oidcd`, end to end:

1. `GET /.well-known/openid-configuration` and `GET
   /.well-known/jwks.json` -- both return well-formed JSON with every
   URL/key OpenShift's OIDC client needs.
2. `GET /authorize?response_type=code&client_id=...&redirect_uri=...`
   -- renders a login form with the request's `client_id`/
   `redirect_uri`/`scope`/`state`/`nonce` preserved as hidden fields.
   An unregistered `client_id`, or a registered one with a
   `redirect_uri` that doesn't match its registration, gets a `400`
   instead of ever redirecting -- required so this can never become an
   open redirector.
3. Submitting the login form with a real user's correct password
   redirects to the client's `redirect_uri` with a one-time
   authorization `code` + the original `state`; the wrong password
   re-renders the form with an error instead of redirecting.
4. `POST /token` (`grant_type=authorization_code`) exchanges that code
   for a signed ID token + access token; decoding the ID token's
   payload confirms `iss`/`sub`/`aud`/`nonce`/`email`/`name`/
   `preferred_username` are all correct, and re-submitting the *same*
   code a second time correctly fails closed (`invalid_grant`) --
   proving the one-time-use guarantee, not just that issuance works.
5. `GET /userinfo` with the access token returns the same claims,
   re-read live from the directory; an invalid/garbage bearer token is
   rejected.
6. **Independently verified the ID token's ES256 signature** using
   Python's `cryptography` library (a real, standards-compliant ECDSA
   implementation with no connection to this codebase) against the
   public key published in `/.well-known/jwks.json` -- confirming the
   signature is a genuinely valid, spec-correct ES256 signature, not
   merely self-consistent within `iron-oidc`'s own verify function. A
   deliberately tampered signing input was also confirmed to fail
   verification.

## Known simplifications (D10, documented rather than silently absent)

- **No signing-key persistence.** `iron-oidcd` generates a fresh ES256
  keypair at every process start; a restart invalidates every
  previously-issued token and the previously-published JWKS. Fine for
  a first vertical slice, not production-hardened -- a real deployment
  would need to load/save the key (e.g. a configured file path).
- **In-memory-only state.** Authorization codes and the signing key
  live in one process's memory, not fastetcd -- this doesn't
  horizontally scale past a single `iron-oidcd` replica yet.
- **No built-in TLS termination.** Plain HTTP; OpenShift's own
  edge/reencrypt Routes are the intended place to terminate TLS in
  front of this service in that environment.
- **The D9 cross-forest brokering hook is out of scope here** -- this
  is a single-forest, single-issuer server, not a broker across
  multiple forests' `iron-oidcd` instances.
