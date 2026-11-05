#!/bin/sh
# Real-Kerberos tests of the `gssapi-system` backend: starts a throwaway MIT KDC
# in a temp directory (realm TEST.LOCAL, principals alice and
# socks/kdc.test.local; that name is mapped to 127.0.0.1 in /etc/hosts, which
# needs sudo: a dotted name that no resolver search domain can rewrite),
# gets alice a ticket, and runs the `#[ignore]`d tests of
# crates/resocks5-net/src/session/auth/gssapi/system.rs against it.
#
# Needs krb5-kdc, krb5-admin-server (kdb5_util, kadmin.local, krb5kdc), the
# Kerberos client tools (kinit) and libkrb5-dev. Run by the `gssapi-system` job
# of .github/workflows/ci.yml; apart from the /etc/hosts line nothing outside
# the temp directory is touched.
set -eu

PATH="$PATH:/usr/sbin:/sbin"
host=kdc.test.local
grep -q " $host" /etc/hosts || echo "127.0.0.1 $host" | sudo tee -a /etc/hosts > /dev/null
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
[domain_realm]
    .test.local = TEST.LOCAL
    test.local = TEST.LOCAL
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
kadmin.local -r TEST.LOCAL -q "addprinc -randkey socks/$host" > /dev/null
kadmin.local -r TEST.LOCAL -q "ktadd -k $root/keytab socks/$host" > /dev/null

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
export GSS_TEST_SERVICE="socks@$host"
cargo test -p resocks5-net --features gssapi-system --locked -- --ignored --test-threads=1 gssapi::system

# Interoperability: a third-party client (curl) against our server over real
# Kerberos. Stock curl up to 8.11 (Ubuntu's 8.5.0 included) keeps its "GSS-API
# allowed" flag in a local variable that is lost whenever the SOCKS5 state
# machine returns to wait for the reply, so it rejects method 1 as "per-message
# authentication is not supported" unless the reply is already buffered. Current
# releases keep it in the options, so build one (checksum pinned).
curl_version=8.23.0
curl_sha256=8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5
curl -fsSL -o "$root/curl.tar.xz" "https://github.com/curl/curl/releases/download/curl-8_23_0/curl-$curl_version.tar.xz"
echo "$curl_sha256  $root/curl.tar.xz" | sha256sum -c -
mkdir "$root/curl-src"
tar -xJf "$root/curl.tar.xz" -C "$root/curl-src" --strip-components=1
(
    cd "$root/curl-src"
    ./configure --prefix="$root/curl" --with-openssl --with-gssapi --disable-shared \
        --without-libpsl --without-libidn2 --without-nghttp2 --without-brotli --without-zstd \
        --disable-ldap --disable-manual > /dev/null
    make -j"$(nproc)" > /dev/null
    make install > /dev/null
)
curl_bin="$root/curl/bin/curl"
"$curl_bin" --version
"$curl_bin" --version | grep -qi "gss" || { echo "kdc-test: the built curl has no GSS-API" >&2; exit 1; }
cargo build -p resocks5-net --features gssapi-system --example gssapi_interop_server --locked
port=1081
"${CARGO_TARGET_DIR:-target}/debug/examples/gssapi_interop_server" "127.0.0.1:$port" "$GSS_TEST_SERVICE"     > "$root/interop.out" 2> "$root/interop.err" &
server_pid=$!
tries=0
until grep -q '^READY' "$root/interop.out" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || { echo "kdc-test: interop server did not start" >&2; cat "$root/interop.err" >&2; exit 1; }
    sleep 1
done
body=$("$curl_bin" -sS -v --max-time 30 --socks5-hostname "$host:$port" --socks5-gssapi-service socks "http://target.test:80/" 2> "$root/curl.err") || {
    echo "kdc-test: curl failed" >&2
    cat "$root/curl.err" "$root/interop.out" "$root/interop.err" >&2
    exit 1
}
wait "$server_pid" || { echo "kdc-test: interop server failed" >&2; cat "$root/interop.err" >&2; exit 1; }
cat "$root/interop.out"
[ "$body" = "ok" ] || { echo "kdc-test: unexpected body: $body" >&2; exit 1; }
grep -q "principal=alice@TEST.LOCAL target=target.test:80 method=Gssapi" "$root/interop.out"     || { echo "kdc-test: the server did not see the expected client" >&2; exit 1; }
echo "kdc-test: curl --socks5-gssapi interoperates"
