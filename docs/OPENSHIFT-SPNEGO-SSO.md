# SPNEGO desktop→console SSO (#16, D7)

No new code: this reuses the Tier 1 KDC (`iron-kdc`, #5) exactly as
built. The "SSO" here is entirely a matter of external, standard
infrastructure -- an authenticating reverse proxy (`mod_auth_gssapi`)
performing SPNEGO/Kerberos negotiation, in front of OpenShift's
`RequestHeader` identity provider -- documented rather than built here,
per D7: "SPNEGO reuses the Tier 1 KDC; integration is an external
authenticating proxy (RequestHeader IdP), documented rather than built
here."

## How this SSO actually works

Unlike #14's LDAP IdP or #15's native OIDC IdP (both of which
`oauth-server` talks to directly), OpenShift has no native SPNEGO
support. The standard pattern (also how Red Hat SSO/Keycloak and IdM
integrate desktop SSO with OpenShift) is:

1. A reverse proxy in front of `oauth-server`'s login/challenge URLs,
   running `mod_auth_gssapi`, protects a small set of URLs with
   `AuthType GSSAPI` -- a domain-joined desktop with a Kerberos ticket
   (from `iron-kdc`) authenticates to the proxy via SPNEGO, completely
   invisibly to the user (no password prompt).
2. On success, `mod_auth_gssapi` sets `REMOTE_USER` to the
   authenticated principal; the proxy forwards the request to
   `oauth-server` with that identity in a trusted header.
3. OpenShift's `RequestHeader` identity provider reads that header and
   trusts it -- it never performs the Kerberos exchange itself.

```yaml
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
    - name: irondirectory-spnego
      mappingMethod: claim
      type: RequestHeader
      requestHeader:
        challengeURL: "https://spnego-proxy.g10.lo/challenging-proxy/oauth/authorize?${query}"
        loginURL: "https://spnego-proxy.g10.lo/login-proxy/oauth/authorize?${query}"
        clientCommonNames: ["spnego-proxy.g10.lo"]
        headers: ["X-Remote-User"]
        ca:
          name: irondirectory-spnego-proxy-ca
```

`clientCommonNames` + `ca` pin this to mutual-TLS from the specific
proxy host -- required, since `RequestHeader` blindly trusts whatever
value shows up in `X-Remote-User`; without that pinning, anything able
to reach `oauth-server` directly could forge an identity.

The proxy side (`mod_auth_gssapi`, on `spnego-proxy.g10.lo`):

```apache
<Location /challenging-proxy/oauth/authorize>
  AuthType GSSAPI
  AuthName "irondirectory Kerberos SSO"
  GssapiCredStore keytab:/etc/httpd/conf/http.keytab
  Require valid-user
  RequestHeader set X-Remote-User %{REMOTE_USER}s
</Location>
```

`/etc/httpd/conf/http.keytab` is a `HTTP/spnego-proxy.g10.lo@REALM`
keytab -- exported exactly the way #8 already established, via
`iron-kdc-ctl export-keytab HTTP/spnego-proxy.g10.lo
/etc/httpd/conf/http.keytab`.

## Live verification (#16)

Standing up OpenShift's `RequestHeader` IdP itself needs nothing new
from this project to test -- it's a header-trust mechanism, no
Kerberos code of its own. The thing actually worth verifying is whether
`iron-kdc`-issued tickets and exported keytabs interoperate with a real
`mod_auth_gssapi`, since that's the SPNEGO acceptor every part of this
flow depends on and it's a *different*, independently-implemented GSS
acceptor than the ones already proven in earlier issues (`iron-ldap`'s
own SASL/GSSAPI bind, #7; OpenSSH's `sshd` and rocketsmbd's SMB
`sec=krb5`, #8).

Verified on a disposable Fedora VM (destroyed afterward): real
`iron-kdcd` serving a throwaway realm, a `HTTP/<fqdn>@REALM` keytab
exported via `iron-kdc-ctl export-keytab` and installed for a real
`httpd` + `mod_auth_gssapi`-protected `<Location>`, and a real user
principal.

- **No credentials at all:** `curl http://.../protected/` → `401`.
- **`kinit alice@REALM`** against `iron-kdcd` succeeds, obtaining a real
  TGT.
- **`curl --negotiate -u : http://.../protected/`** performs a genuine
  SPNEGO exchange -- confirmed by the response's `WWW-Authenticate:
  Negotiate <mutual-auth token>` header -- and gets `200 OK` with the
  protected content, proving `mod_auth_gssapi` correctly validated an
  `AP-REQ` built from `iron-kdc`'s TGT/service-ticket issuance against
  the `iron-kdc`-exported keytab.
- **Apache's own access log** (`%u`, the authenticated remote user)
  shows `alice@G16SPNEGO.LO` for that request, not `-` -- confirming
  `mod_auth_gssapi` identified the correct principal, exactly the value
  it would forward as `REMOTE_USER`/`X-Remote-User` to OpenShift's
  `RequestHeader` IdP.
- **`kdestroy` then retry:** `curl --negotiate` (now with no ticket)
  correctly falls back to `401`.

This is the same "reproduce the exact mechanism live rather than stand
up the whole downstream product" approach #14/#15 used: OpenShift's
`RequestHeader` IdP itself is a trivial, already-battle-tested
mechanism (a header check); the SPNEGO/`mod_auth_gssapi` half is the
piece that actually depends on this project's Kerberos implementation,
and that's what was verified against a real, independent GSS acceptor.

## Known simplifications

- The proxy's own TLS (needed for `clientCommonNames`/`ca` pinning in
  the real `OAuth` CR above) wasn't part of this verification --
  covered by the same TLS machinery `iron-ldap`/`iron-gc` already have
  (`docs/FIPS.md`), not something SPNEGO itself needs.
- Group/claim mapping beyond the bare authenticated principal
  (`clientCommonNames`, `headers`) is entirely OpenShift/proxy-side
  configuration, out of scope for this project's own code either way.
