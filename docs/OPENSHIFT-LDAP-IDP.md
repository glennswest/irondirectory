# OpenShift LDAP identity provider (#14, D7)

No new code: `iron-ldap` already speaks plain LDAPv3 simple bind + search
(#4), which is all OpenShift's built-in `LDAPPasswordIdentityProvider`
needs. This is the "ship first" Tier 1 SSO surface — direct bind, no
token exchange, no cross-app SSO (that's `iron-oidc`, Phase 1.5, #15).

## How OpenShift's LDAP IdP actually authenticates a login

There is no OpenShift-specific protocol here — `oauth-server` does exactly
two LDAP operations per login attempt, both already covered by `iron-ldap`
(#4, #7):

1. **Search** — bind as `bindDN`/`bindPassword` (or anonymously, if both
   are left empty) and search the configured base DN for an entry matching
   the login-name attribute (commonly `uid`).
2. **Bind** — take the DN the search found and issue a second, ordinary
   simple bind using *that DN* and the password the user typed into the
   OpenShift login form. Success = authenticated; the configured
   `attributes.id`/`name`/`email`/`preferredUsername` are read off the
   found entry to build the OpenShift `Identity`/`User` objects.

Nothing here is exotic: it is exactly the `ldapsearch` + `ldapsearch -D`
sequence any LDAP client already does, and it needs no schema beyond what
`iron-ldap`'s existing AD/RFC 2307 validation (#4) already accepts
(`inetOrgPerson`/`posixAccount`-shaped entries with `uid`/`cn`/`mail`).

## Configuration

```yaml
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
    - name: irondirectory
      mappingMethod: claim
      type: LDAP
      ldap:
        attributes:
          id: ["dn"]
          preferredUsername: ["uid"]
          name: ["cn"]
          email: ["mail"]
        bindDN: ""              # anonymous search bind; set a real
                                 # bindDN/bindPassword Secret for a
                                 # deployment that disables anonymous bind
        bindPassword:
          name: ldap-bind-password  # only referenced if bindDN is set
        insecure: true           # see "TLS" below
        url: "ldap://il1.g8.lo:389/dc=g10,dc=lo?uid?sub?(objectClass=posixAccount)"
```

The `url` field is an RFC 2255 LDAP URL: `<scheme>://<host>/<base>?<attr>?<scope>?<filter>`.
OpenShift substitutes the typed username into `<attr>` to build the search
filter (`(&(objectClass=posixAccount)(uid=<username>))` for the example
above), exactly matching the `ldapsearch` call verified below.

### High availability

Point `url` at the load-balanced/redundant LDAP tier, not a single node —
this deployment already runs `iron-ldapd` redundantly on `il1`/`il2`/`il3.g8.lo`
(#4). OpenShift's LDAP IdP does not itself retry across multiple hosts, so
the `host` in the URL should be whatever already fronts those three (a
VIP/LB), matching how any other LDAP client in this environment reaches
the directory.

### TLS

`insecure: true` (plain `ldap://`) is what was verified live below, since
the `il1`/`il2`/`il3.g8.lo` instances used for this pass don't have
`IRON_LDAP_TLS_CERT`/`IRON_LDAP_TLS_KEY` configured. For a production
deployment, set `insecure: false` and either:

- `ldaps://` against `IRON_LDAP_LDAPS_LISTEN` (a dedicated implicit-TLS
  port, 636 by convention), or
- StartTLS is *not* an option here — OpenShift's LDAP IdP only supports
  implicit LDAPS or plain LDAP via the `insecure` flag, it does not speak
  StartTLS.

`ldap.ca` (a `ConfigMap` key) should hold the CA that signed whatever
cert `IRON_LDAP_TLS_CERT` points at.

## Live verification (#14)

No new `iron-ldap` code was needed, so verification means proving the
*documented configuration* actually authenticates, not testing new code.
Rather than standing up a full OpenShift cluster to exercise a
well-established, already-supported upstream feature (disproportionate
effort for what the roadmap explicitly scopes as "ship first, no new
code"), the exact two-step search-then-bind sequence `oauth-server`
performs was reproduced directly against the real, already-deployed
`il1.g8.lo` — proving the underlying mechanism, not just asserting it
should work.

A test entry was added (RFC 2307 `posixAccount` + `inetOrgPerson`,
mirroring the `objectClass=posixAccount` filter in the `url` above):

```
dn: cn=ocptest,dc=g10,dc=lo
objectClass: top
objectClass: person
objectClass: inetOrgPerson
objectClass: posixAccount
cn: ocptest
sn: TestUser
mail: ocptest@g10.lo
uid: ocptest
uidNumber: 50001
gidNumber: 50001
homeDirectory: /home/ocptest
userPassword: OcpTestSecret123!
```

**Search phase** (anonymous, matching `bindDN: ""` above):

```
$ ldapsearch -x -H ldap://il1.g8.lo -b "dc=g10,dc=lo" -s sub \
    "(&(objectClass=posixAccount)(uid=ocptest))" dn cn mail uid
dn: cn=ocptest,dc=g10,dc=lo
cn: ocptest
mail: ocptest@g10.lo
uid: ocptest
result: 0 Success
```

**Bind phase** with the correct password — succeeds:

```
$ ldapsearch -x -H ldap://il1.g8.lo \
    -D "cn=ocptest,dc=g10,dc=lo" -w "OcpTestSecret123!" \
    -b "cn=ocptest,dc=g10,dc=lo" -s base "(objectclass=*)" cn
dn: cn=ocptest,dc=g10,dc=lo
cn: ocptest
result: 0 Success
```

**Bind phase** with the wrong password — fails closed, exactly as
`oauth-server` requires to reject the login:

```
$ ldapsearch -x -H ldap://il1.g8.lo \
    -D "cn=ocptest,dc=g10,dc=lo" -w "WrongPassword" \
    -b "cn=ocptest,dc=g10,dc=lo" -s base "(objectclass=*)" cn
ldap_bind: Invalid credentials (49)
```

(The test entry was removed after verification — `il1`/`il2`/`il3.g8.lo`
are a real, ongoing shared deployment, not a throwaway test forest.)

A `ldapwhoami` bind against the same DN/password separately fails with
"Protocol error: extended operations are not implemented yet" — that is
RFC 4532's WhoAmI *extended operation*, an entirely different mechanism
from a simple bind, and OpenShift's LDAP IdP never issues it. Not a gap
relevant to this issue; tracked as its own follow-up (`iron-ldap`'s
extended-operation support beyond StartTLS).

## Known limitation carried over from #4

irondirectory has no authorization/ACL model yet — any bind (including
anonymous) can currently write. This is a pre-existing gap tracked
elsewhere, not something #14 introduces or needs to fix: OpenShift's LDAP
IdP only ever *reads* (search) and *authenticates* (bind), it never
writes to the directory.
