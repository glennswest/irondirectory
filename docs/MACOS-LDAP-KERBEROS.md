# macOS light path: LDAPv3 identity + Kerberos (#22)

A Mac that is **not** joined to the domain (that is `dsconfigad`, Phase 2,
#20) can still take its users from irondirectory: the built-in LDAPv3 plugin
resolves users and groups from `iron-ldapd` with the RFC 2307 mappings, and
Kerberos gets a TGT from `iron-kdcd`. This is the macOS half of D6's Tier 1,
beside RHEL/SSSD (#7).

**Status.** The server half is checked by `test/macos-ldap-e2e.sh` (real
`ldapsearch`/`ldapwhoami`/`kinit` against `iron-ldapd`/`iron-kdcd`, making
the lookups the RFC 2307 mapping makes). The Mac half below has **not yet
been run on a Mac** against this stack: it waits for a stack a Mac can reach
(#25's golden + operator). Record what each check prints when it is run.

## 1. Server side: a user and a group

Kerberos principal first (`set-password` creates `cn=<name>,<base>` when the
principal is new), then the posix attributes and the LDAP password on the
same entry. Run with the usual `IRON_KDC_*` settings
([CONFIGURATION.md](CONFIGURATION.md)):

```sh
iron-kdc-ctl set-password alice '<kerberos password>'
ldapmodify -x -H ldap://<ldap-host> -D cn=administrator,<base> -W <<'LDIF'
dn: cn=alice,<base>
changetype: modify
add: objectClass
objectClass: inetOrgPerson
objectClass: posixAccount
-
add: uid
uid: alice
-
add: sn
sn: Liddell
-
add: uidNumber
uidNumber: 5001
-
add: gidNumber
gidNumber: 5000
-
add: homeDirectory
homeDirectory: /Users/alice
-
add: loginShell
loginShell: /bin/zsh
-
add: userPassword
userPassword: <ldap password>
LDIF

ldapadd -x -H ldap://<ldap-host> -D cn=administrator,<base> -W <<'LDIF'
dn: cn=ironstaff,<base>
objectClass: top
objectClass: posixGroup
cn: ironstaff
gidNumber: 5000
memberUid: alice
LDIF
```

The LDAP password (`userPassword`, what an LDAP bind checks) and the
Kerberos password (`krbkey`, what `kinit` checks) are **separate today**:
setting one does not set the other (#56). Set both, to the same value if
users are to see one password.

Pick `uidNumber`s above the Mac's local range (macOS local users start at
501).

## 2. On the Mac: Kerberos

`/etc/krb5.conf` (as root; macOS's Heimdal reads it):

```ini
[libdefaults]
    default_realm = CORP.EXAMPLE.LO
    dns_lookup_kdc = true
[realms]
    CORP.EXAMPLE.LO = {
        kdc = <kdc-host>
    }
[domain_realm]
    .corp.example.lo = CORP.EXAMPLE.LO
```

With `iron-dns` SRV records published (#6) the `kdc` line can go. Then:

```sh
kinit alice@CORP.EXAMPLE.LO
klist                      # expect krbtgt/CORP.EXAMPLE.LO@CORP.EXAMPLE.LO
```

Keep the KDC up while testing from a Mac: each moment nothing listens on
UDP 88, the KDC host answers ICMP port-unreachable, and macOS caches it for
that destination, after which every UDP packet to the host fails at once
(`EHOSTUNREACH`) and Kerberos looks broken. Clear it with
`sudo route -n delete <kdc-ip> && sudo arp -d <kdc-ip>` (seen on #20).

## 3. On the Mac: the LDAPv3 plugin

Directory Utility (System Settings → Users & Groups → Network Account
Server → Edit… → Open Directory Utility, or
`/System/Library/CoreServices/Applications/Directory Utility.app`):

1. **Services → LDAPv3 → Edit… → New…**: server name `<ldap-host>`; leave
   *Encrypt using SSL* off for `ldap://`, on for LDAPS (iron-ldapd with
   `IRON_LDAP_TLS_CERT`/`_KEY`); **Manual**.
2. **Edit… → Search & Mappings**: *Access this LDAPv3 server using*
   **RFC2307 (Unix)**; *Search base suffix* `<base>` (e.g.
   `dc=corp,dc=example,dc=lo`).
3. **Search Policy → Authentication**: add `/LDAPv3/<ldap-host>`.

From a shell instead, `sudo dsconfigldap -a <ldap-host> -n iron` adds the
server; it has no option for the mappings, so step 2 is still done in
Directory Utility. The search path:
`sudo dscl /Search -append / CSPSearchPath /LDAPv3/<ldap-host>`.

What the plugin then asks iron-ldapd (anonymously, as it binds by default),
and `test/macos-ldap-e2e.sh` checks:

| Mac record | LDAP filter |
|---|---|
| user by name | `(&(objectClass=posixAccount)(uid=alice))` |
| user by UniqueID | `(&(objectClass=posixAccount)(uidNumber=5001))` |
| every user | `(objectClass=posixAccount)` |
| name search | `(&(objectClass=posixAccount)(\|(uid=ali*)(cn=ali*)))` |
| group by PrimaryGroupID | `(&(objectClass=posixGroup)(gidNumber=5000))` |
| groups of a user | `(&(objectClass=posixGroup)(memberUid=alice))` |

Mapped attributes: RecordName `uid`, RealName `cn`, UniqueID `uidNumber`,
PrimaryGroupID `gidNumber`, NFSHomeDirectory `homeDirectory`, UserShell
`loginShell`; groups RecordName `cn`, GroupMembership `memberUid`.

## 4. On the Mac: the checks (#22's acceptance)

```sh
dscacheutil -flushcache
dscl /LDAPv3/<ldap-host> -read /Users/alice
    # expect UniqueID: 5001, PrimaryGroupID: 5000,
    # NFSHomeDirectory: /Users/alice, UserShell: /bin/zsh
dscl /Search -read /Users/alice UniqueID
id alice
    # expect uid=5001(alice) gid=5000(ironstaff) groups=5000(ironstaff)...
dscl /LDAPv3/<ldap-host> -read /Groups/ironstaff
dscl /LDAPv3/<ldap-host> -authonly alice
    # an LDAP bind as alice's DN; over ldap:// the password crosses in clear
kinit alice@CORP.EXAMPLE.LO && klist
```

Undo: remove the server in Directory Utility (or
`sudo dsconfigldap -r <ldap-host>`), then `dscacheutil -flushcache`, and
restore `/etc/krb5.conf`.
