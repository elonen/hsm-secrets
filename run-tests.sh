#!/bin/bash
set -e

TEMPDIR=$(mktemp -d /tmp/hsm-secret-test.XXXXXX)
[[ $TEMPDIR =~ ^/tmp/hsm-secret-test ]] || { echo "Error: Invalid temp directory"; exit 1; }
trap "rm -rf $TEMPDIR" EXIT

cp hsm-conf.yml $TEMPDIR/
MOCKDB="$TEMPDIR/mock.pickle"
CMD="./_venv/bin/hsm-secrets -c $TEMPDIR/hsm-conf.yml --mock $MOCKDB"


# Helpers for `expect` calls:
# - Preamble sets up an infallible timeout handler.
# - Postamble reads the exit status of the last spawned process and exits with it.
EXPECT_PREAMBLE='
    set timeout 5
    proc handle_timeout {} { puts "Timeout. Aborting."; catch {exec kill -9 [exp_pid]}; exit 1 } '
EXPECT_POSTAMBLE='
    set wait_result [wait]
    if {[llength $wait_result] == 4} {
        lassign $wait_result pid spawnid os_error_flag value
        if {$os_error_flag == 0} { puts "exit status: $value"; exit $value }
        else { puts "errno: $value"; exit 1 }
    } else { puts "Unexpected wait result"; exit 1 } '


run_cmd() {
    echo "$ $CMD $@"
    $CMD "$@"
}

assert_success() {
    if [ $? -ne 0 ]; then
        echo "ERROR: Expected success, but command failed"
        return 1
    fi
}

assert_grep() {
    if ! grep -q "$1" <<< "$2"; then
        echo "ERROR: Expected output to contain '$1'"
        return 1
    fi
}

setup() {
    run_cmd -q hsm compare --create
    run_cmd x509 create -a
    # `add-service` command is interactive => use `expect` to provide input
    expect << EOF
        $EXPECT_PREAMBLE
        spawn sh -c "$CMD user add-service 0x0008 2>&1"
        expect {
            "Press ENTER" { sleep 0.1; send "\r"; exp_continue }
            "3031-3233-3031" { sleep 0.1; send "\r"; exp_continue }
            "again to confirm" { sleep 0.1; send "3031-3233-3031-3233-3031-3233-3031-3233"; sleep 0.1; send "\r"; exp_continue }
            timeout { handle_timeout }
            eof {}
        }
        $EXPECT_POSTAMBLE
EOF
    run_cmd -q hsm make-wrap-key
}

# ------------------ test cases -------------------------

test_fresh_device() {
    local count=$(run_cmd -q hsm list-objects | grep -c '^0x')
    [ "$count" -eq 1 ] || { echo "Expected 1 object, but found $count"; return 1; }
}

test_create_all() {
    setup
    local count=$(run_cmd -q hsm compare | grep -c '\[x\]')
    [ "$count" -eq 35 ] || { echo "Expected 35 objects, but found $count"; return 1; }
}

test_ssh_certificates() {
    setup
    run_cmd ssh get-ca --all | ssh-keygen -l -f /dev/stdin
    assert_success

    ssh-keygen -t ed25519 -f $TEMPDIR/testkey -N '' -C 'testkey'
    run_cmd ssh sign -u test.user -p users,admins $TEMPDIR/testkey.pub
    assert_success

    local output=$(ssh-keygen -L -f $TEMPDIR/testkey-cert.pub)
    assert_success
    assert_grep "Public key: ED25519" "$output"
    assert_grep "^[[:space:]]*users$" "$output"
    assert_grep "^[[:space:]]*admins$" "$output"
    assert_grep 'Key ID: "test.user-[0-9]*-users+admins"' "$output"
}

test_tls_certificates() {
    setup
    run_cmd -q x509 get --all | openssl x509 -text -noout
    assert_success

    run_cmd tls server-cert --out $TEMPDIR/www-example-com.pem --common-name www.example.com --san-dns www.example.org --san-ip 192.168.0.1 --san-ip fd12:123::80 --keyfmt rsa4096
    assert_success

    local output=$(openssl crl2pkcs7 -nocrl -certfile $TEMPDIR/www-example-com.cer.pem | openssl pkcs7 -print_certs | openssl x509 -text -noout)
    assert_success
    assert_grep 'Subject:.*CN=www.example.com.*L=Duckburg.*ST=Calisota.*C=US' "$output"
    assert_grep 'DNS:www.example.org' "$output"
    assert_grep 'IP Address:192.168.0.1' "$output"
    assert_grep 'IP Address:FD12:123' "$output"
    assert_grep 'Public.*4096' "$output"
    assert_grep 'Signature.*ecdsa' "$output"

    [ -f $TEMPDIR/www-example-com.key.pem ] || { echo "ERROR: Key not saved"; return 1; }
    [ -f $TEMPDIR/www-example-com.csr.pem ] || { echo "ERROR: CSR not saved"; return 1; }
    [ -f $TEMPDIR/www-example-com.chain.pem ] || { echo "ERROR: Chain bundle not saved"; return 1; }
}

test_password_derivation() {
    setup
    local output=$(run_cmd -q pass get www.example.com)
    assert_grep 'dignity.proud.material.upset.elegant.finish' "$output"

    local nonce=$(run_cmd -q pass rotate www.example.com | grep nonce)
    sed -E "s|^( *)\-.*name_hmac.*nonce.*ts.*$|\1${nonce}|" < $TEMPDIR/hsm-conf.yml > $TEMPDIR/rotated-conf.yml
    mv $TEMPDIR/rotated-conf.yml $TEMPDIR/hsm-conf.yml

    output=$(run_cmd -q pass get www.example.com)
    ! grep -q 'dignity.proud.material.upset.elegant.finish' <<< "$output" || { echo "ERROR: password not rotated"; return 1; }
}

test_wrapped_backup() {
    setup
    run_cmd -q hsm backup --out $TEMPDIR/backup.tgz
    assert_success

    tar tvfz $TEMPDIR/backup.tgz | grep -q 'ASYMMETRIC_KEY' || { echo "ERROR: No asymmetric keys found in backup"; return 1; }
    tar tvfz $TEMPDIR/backup.tgz | grep -q 'OPAQUE' || { echo "ERROR: No certificates found in backup"; return 1; }

    run_cmd -q hsm delete --force 0x0210
    run_cmd -q hsm compare | grep -q '[ ].*ca-root-key-rsa' || { echo "ERROR: Key not deleted"; return 1; }

    run_cmd -q hsm restore --force $TEMPDIR/backup.tgz
    run_cmd -q hsm compare | grep -q '[x].*ca-root-key-rsa' || { echo "ERROR: Key not restored"; return 1; }
}

# ------------------------------------------------------

function run_test_quiet() {
    echo -n "  $1 ... "
    local output
    if output=$($1 2>&1); then
        echo "OK"
    else
        echo "FAILED"
        echo "Error output:"
        echo "$output"
        return 1
    fi
    rm -f $MOCKDB
}

run_test() {
    echo -n "  $1 ... "
    if $1; then
        echo "OK"
    else
        echo "FAILED"
        return 1
    fi
    rm -f $MOCKDB
}

echo "Running tests:"
run_test test_fresh_device
run_test test_create_all
run_test test_ssh_certificates
run_test test_tls_certificates
run_test test_password_derivation
run_test test_wrapped_backup

echo "All tests passed successfully!"
