#!/bin/sh
# Real-Kerberos tests of the `gssapi-system` backend: starts a throwaway MIT KDC
# in a temp directory (realm TEST.LOCAL, principals alice and socks/localhost),
# gets alice a ticket, and runs the `#[ignore]`d tests of
# crates/resocks5-net/src/session/auth/gssapi/system.rs against it.
#
# Needs krb5-kdc, krb5-admin-server (kdb5_util, kadmin.local, krb5kdc), the
# Kerberos client tools (kinit) and libkrb5-dev. Run by the `gssapi-system` job
# of .github/workflows/ci.yml; nothing outside the temp directory is touched.
set -eu

PATH="$PATH:/usr/sbin:/sbin"
root=$(mktemp -d)
kdc_pid=
cleanup() {
    [ -z "$kdc_pid" ] || kill "$kdc_pid" 2>/dev/null || true
    rm -rf -- "$root"
}
trap cleanup 0

export KRB5_CONFIG="$root/krb5.conf"
export KRB5_KDC_PROFILE="$root/kdc.conf"
export KRB5CCNAME="FILE:$root/ccache"
export KRB5_KTNAME="FILE:$root/keytab"

cat > "$KRB5_CONFIG" <<EOF
[libdefaults]
    default_realm = TEST.LOCAL
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false
    udp_preference_limit = 1
[realms]
    TEST.LOCAL = {
        kdc = 127.0.0.1:8888
    }
EOF

cat > "$KRB5_KDC_PROFILE" <<EOF
[kdcdefaults]
    kdc_ports = 8888
    kdc_tcp_ports = 8888
[realms]
    TEST.LOCAL = {
        database_name = $root/principal
        key_stash_file = $root/stash
        acl_file = $root/kadm5.acl
        max_life = 1d
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
    }
EOF
: > "$root/kadm5.acl"

kdb5_util create -s -r TEST.LOCAL -P master-password > /dev/null
kadmin.local -r TEST.LOCAL -q "addprinc -pw alice-password alice" > /dev/null
kadmin.local -r TEST.LOCAL -q "addprinc -randkey socks/localhost" > /dev/null
kadmin.local -r TEST.LOCAL -q "ktadd -k $root/keytab socks/localhost" > /dev/null

krb5kdc -n -P "$root/kdc.pid" &
kdc_pid=$!
# The KDC answers on TCP 8888 once it is up.
tries=0
until printf 'alice-password\n' | kinit alice 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || { echo "kdc-test: the KDC did not come up" >&2; exit 1; }
    sleep 1
done
klist

export GSS_TEST_PRINCIPAL=alice@TEST.LOCAL
cargo test -p resocks5-net --features gssapi-system --locked -- --ignored --test-threads=1 gssapi::system
