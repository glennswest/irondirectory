# Password policy

The domain's password policy (#70) is Active Directory's: five attributes on
the domain head entry (the partition's base DN, e.g. `dc=iron,dc=g8,dc=lo`),
read on every password set. Code: `crates/kdc/src/policy.rs`
(`iron_kdc::policy`). Test: `test/password-policy-e2e.sh`.

| attribute          | meaning | encoding |
|--------------------|---------|----------|
| `minPwdLength`     | minimum length, in characters | integer; never below 8 (the FIPS PBKDF2 minimum, `docs/FIPS.md`) |
| `pwdHistoryLength` | a change may not reuse any of the last N passwords, the current one included | integer, at most 24 |
| `pwdProperties`    | bit `0x1` (`DOMAIN_PASSWORD_COMPLEX`) turns on the complexity rules | flag word |
| `minPwdAge`        | how long a password must be kept before its holder changes it | AD interval: negative 100 ns ticks (`-864000000000` = 1 day); `0` = none |
| `maxPwdAge`        | how long a password lasts | as `minPwdAge`; `0` or `-9223372036854775808` = never |

An attribute that is absent is not enforced. A domain with none of them has
the 8-character floor and nothing else. `iron-bootstrap` sets none.

Set them as an administrator over LDAP, as on AD:

```
ldapmodify -x -H ldap://il1.g8.lo -D cn=administrator,dc=iron,dc=g8,dc=lo -W <<EOF
dn: dc=iron,dc=g8,dc=lo
changetype: modify
replace: minPwdLength
minPwdLength: 12
-
replace: pwdHistoryLength
pwdHistoryLength: 24
-
replace: pwdProperties
pwdProperties: 1
-
replace: minPwdAge
minPwdAge: -864000000000
-
replace: maxPwdAge
maxPwdAge: -36288000000000
EOF
```

## Which rules apply

| rule        | own password (change) | another's (reset by an administrator) |
|-------------|-----------------------|---------------------------------------|
| length      | yes | yes |
| complexity  | yes | yes |
| history     | yes | no  |
| minimum age | yes | no  |

Machine accounts (`sAMAccountName` ending in `$`, objectClass `computer`, or
a trust-account bit in `userAccountControl`) are held to the length only.

Complexity, as AD's "Password must meet complexity requirements": the
password may not contain the `sAMAccountName` (when it is longer than two
characters) nor any part of the `displayName` of three or more characters
(split on `, . - _ #`, space and tab), ignoring case; and it uses at least
three of: upper case, lower case, digits, other symbols, letters with no case.

## Where it is checked

| path | change or reset | a refusal is |
|------|-----------------|--------------|
| kpasswd (RFC 3244, `iron-kdcd` port 464) | change when the target is the ticket's own client, else reset | `KRB5_KPASSWD_SOFTERROR` whose result string is AD's 30-byte policy record (below) |
| LDAP Password Modify (RFC 3062, `iron-ldapd`) | change when the target is the bound DN or bound Kerberos principal, else reset | `constraintViolation`, with the reason |
| `NetrServerPasswordSet2` (`iron-rpcd`) | reset (a machine: length only) | `STATUS_ACCESS_DENIED` |

`iron-kdc-ctl set-password` and `iron-bootstrap` are operator tools and
check nothing.

The kpasswd policy record is what AD sends and what MIT `kpasswd`
(`krb5_chpw_message`) and impacket (`_decodePasswordPolicy`) decode:
big-endian `u16 0`, `u32` minimum length, `u32` history length, `u32`
properties, `u64` maximum age, `u64` minimum age (ages as positive 100 ns
ticks). It says what the policy is, not which rule failed; the KDC's log
line (`kpasswd: refused: ...`) names that.

## Expiry

`iron-kdcd` refuses an AS-REQ for a TGT with `KDC_ERR_KEY_EXPIRED` once the
password is older than `maxPwdAge`, or when `pwdLastSet` is `0` ("must change
at next logon"), after pre-authentication succeeds. A request for a
`kadmin/changepw` ticket is still answered, so MIT `kinit` can prompt for a
new password and set it. Machine accounts, `krbtgt`, accounts with
`DONT_EXPIRE_PASSWD` (`0x10000`) in `userAccountControl`, and entries with no
`pwdLastSet` never expire.

## What is stored

Every password set (`iron_kdc::principal::set_password`, all paths above)
writes on the principal's entry:

- `pwdLastSet`: the time, as a FILETIME (100 ns intervals since 1601-01-01
  UTC), as on AD;
- `krbpwdhistory`: the new password's aes256-cts-hmac-sha384-192 key and its
  salt (`<salt>:<hex key>`) in front of the previous ones, at most 24. No
  password is stored; the history check derives the candidate under each
  salt and compares keys. An entry set before this existed has no history,
  and its current key is compared instead.

`krbpwdhistory` is key material like `krbkey` and must be hidden from
searches with it (#60).
