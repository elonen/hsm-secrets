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
        exit 1
    fi
}

assert_grep() {
    if ! grep -q "$1" <<< "$2"; then
        echo "ERROR: Expected output to contain '$1'"
        exit 1
    fi
}

assert_not_grep() {
    if grep -q "$1" <<< "$2"; then
        echo "ERROR: Expected output not to contain '$1'"
        exit 1
    fi
}

setup() {
    run_cmd -q hsm compare --create
    assert_success

    run_cmd x509 create -a
    assert_success

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
    assert_success

    run_cmd -q hsm make-wrap-key
    assert_success
}

# ------------------ test cases -------------------------

test_fresh_device() {
    local count=$(run_cmd -q hsm list-objects | grep -c '^0x')
    [ "$count" -eq 1 ] || { echo "Expected 1 object, but found $count"; return 1; }
}

test_create_all() {
    setup

    # Run simplified secret sharing command
    expect << EOF
        $EXPECT_PREAMBLE
        spawn sh -c "$CMD hsm admin-sharing-ceremony --skip-ceremony -n 3 -t 2 2>&1"
        expect {
            "airgapped" { sleep 0.1; send "y\r"; exp_continue }
            "admin password" { sleep 0.1; send "passw123\r"; exp_continue }
            "again" { sleep 0.1; send "passw123\r"; exp_continue }
            timeout { handle_timeout }
            eof {}
        }
        $EXPECT_POSTAMBLE
EOF
    assert_success

    local count=$(run_cmd -q hsm compare | grep -c '\[x\]')
    assert_success
    [ "$count" -eq 36 ] || { echo "Expected 36 objects, but found $count"; return 1; }

    # Remove default admin key
    run_cmd hsm default-admin-disable
    assert_success
    local count=$(run_cmd -q hsm compare | grep -c '\[x\]')
    assert_success
    [ "$count" -eq 35 ] || { echo "Expected 35 objects, but found $count"; return 1; }
}

test_tls_certificates() {
    setup
    run_cmd -q x509 get --all | openssl x509 -text -noout
    assert_success

    run_cmd tls server-cert --out $TEMPDIR/www-example-com.pem --common-name www.example.com --san-dns www.example.org --san-ip 192.168.0.1 --san-ip fd12:123::80 --keyfmt rsa4096
    assert_success

    local output=$(openssl crl2pkcs7 -nocrl -certfile $TEMPDIR/www-example-com.cer.pem | openssl pkcs7 -print_certs | openssl x509 -text -noout)
    assert_success
    echo "$output"
    assert_grep 'Subject.*CN.*=.*www.example.com.*L.*=.*Duckburg.*ST.*=.*Calisota.*C.*=.*US' "$output"
    assert_grep 'DNS.*www.example.org' "$output"
    assert_grep 'IP Address.*192.168.0.1' "$output"
    assert_grep 'IP Address.*FD12:123' "$output"
    assert_grep 'Public.*4096' "$output"
    assert_grep 'Signature.*ecdsa' "$output"

    [ -f $TEMPDIR/www-example-com.key.pem ] || { echo "ERROR: Key not saved"; return 1; }
    [ -f $TEMPDIR/www-example-com.csr.pem ] || { echo "ERROR: CSR not saved"; return 1; }
    [ -f $TEMPDIR/www-example-com.chain.pem ] || { echo "ERROR: Chain bundle not saved"; return 1; }
}

test_password_derivation() {
    setup
    local output=$(run_cmd -q pass get www.example.com)
    assert_success
    assert_grep 'dignity.proud.material.upset.elegant.finish' "$output"

    local nonce=$(run_cmd -q pass rotate www.example.com | grep nonce)
    assert_success
    sed -E "s|^( *)\-.*name_hmac.*nonce.*ts.*$|\1${nonce}|" < $TEMPDIR/hsm-conf.yml > $TEMPDIR/rotated-conf.yml
    mv $TEMPDIR/rotated-conf.yml $TEMPDIR/hsm-conf.yml

    output=$(run_cmd -q pass get www.example.com)
    assert_success
    ! grep -q 'dignity.proud.material.upset.elegant.finish' <<< "$output" || { echo "ERROR: password not rotated"; return 1; }
}

test_wrapped_backup() {
    setup
    run_cmd -q hsm backup --out $TEMPDIR/backup.tgz
    assert_success

    tar tvfz $TEMPDIR/backup.tgz | grep -q 'ASYMMETRIC_KEY' || { echo "ERROR: No asymmetric keys found in backup"; return 1; }
    tar tvfz $TEMPDIR/backup.tgz | grep -q 'OPAQUE' || { echo "ERROR: No certificates found in backup"; return 1; }

    run_cmd -q hsm delete --force 0x0210
    assert_success
    run_cmd -q hsm compare | grep -q '[ ].*ca-root-key-rsa' || { echo "ERROR: Key not deleted"; return 1; }
    assert_success

    run_cmd -q hsm restore --force $TEMPDIR/backup.tgz
    assert_success
    run_cmd -q hsm compare | grep -q '[x].*ca-root-key-rsa' || { echo "ERROR: Key not restored"; return 1; }
    assert_success
}

test_ssh_user_certificates() {
    setup
    run_cmd ssh get-ca --all | ssh-keygen -l -f /dev/stdin
    assert_success

    ssh-keygen -t ed25519 -f $TEMPDIR/testkey -N '' -C 'testkey'
    run_cmd ssh sign-user -u test.user -p users,admins $TEMPDIR/testkey.pub
    assert_success

    local output=$(ssh-keygen -L -f $TEMPDIR/testkey-cert.pub)
    assert_success
    assert_grep "Public key: ED25519" "$output"
    assert_grep "^[[:space:]]*users$" "$output"
    assert_grep "^[[:space:]]*admins$" "$output"
    assert_grep 'Key ID: "test.user-[0-9]*-users+admins"' "$output"
}

test_ssh_host_certificates() {
    setup

    # Generate a test host key
    ssh-keygen -t ed25519 -f $TEMPDIR/test_host_key -N '' -C 'test_host'

    # Sign the host key with wildcard principals
    run_cmd ssh sign-host --hostname wiki.example.com --principals "wiki.*,10.0.0.*" $TEMPDIR/test_host_key.pub
    assert_success

    local output=$(ssh-keygen -L -f $TEMPDIR/test_host_key-cert.pub)
    echo "Cert contents:"
    echo "$output"

    assert_success
    assert_grep "Public key: ED25519" "$output"
    assert_grep "Type: ssh-ed25519-cert-v01@openssh.com host certificate" "$output"
    assert_grep "^[[:space:]]*wiki.example.com$" "$output"
    assert_grep "^[[:space:]]*wiki.*$" "$output"
    assert_grep "^[[:space:]]*10.0.0.*$" "$output"
    assert_grep 'Key ID.*host-wiki.example.com-.*' "$output"

}

test_logging_commands() {
    local DB_PATH="$TEMPDIR/test_log.db"
    export HSM_PASSWORD="password123-not-really-set"

    # Test first fetch
    run_cmd --auth-password-id='log-audit' log fetch "$DB_PATH"
    assert_success
    [ -f "$DB_PATH" ] || { echo "ERROR: Log database not created"; return 1; }

    # Apply audit settings
    local apply_output=$(run_cmd log apply-settings --force)
    assert_success
    assert_grep "settings applied" "$apply_output"

    setup   # Create some objects

    # Fetch again twice to log SET_LOG_INDEX due to --clear
    run_cmd --auth-password-id='log-audit' log fetch "$DB_PATH" --clear
    assert_success
    run_cmd --auth-password-id='log-audit' log fetch "$DB_PATH"
    assert_success

    # Test log review
    local review_output=$(run_cmd log review "$DB_PATH")
    assert_success
    echo "$review_output"
    assert_grep "SET_LOG_INDEX" "$review_output"
    assert_grep "DEFAULT AUTHKEY" "$review_output"
    assert_grep "GENERATE_ASYMMETRIC_KEY" "$review_output"
    assert_grep "PUT_OPAQUE" "$review_output"

    # Test log verify-all
    run_cmd log verify-all "$DB_PATH"
    assert_success

    # Test log export
    local export_file="$TEMPDIR/log_export.jsonl"
    run_cmd log export "$DB_PATH" --out "$export_file"
    assert_success
    [ -f "$export_file" ] || { echo "ERROR: Log export file not created"; return 1; }
    local export_content=$(cat "$export_file")
    assert_grep "GENERATE_ASYMMETRIC_KEY" "$export_content"

    # Make an arbitrary test operation and verify that it is logged
    assert_not_grep 'SIGN_HMAC' "$export_file"
    run_cmd -q pass get wiki.example.com
    assert_success

    run_cmd --auth-password-id 'log-audit' log fetch "$DB_PATH" -c
    assert_success
    run_cmd log verify-all "$DB_PATH"
    assert_success

    local export_content=$(run_cmd log export "$DB_PATH")
    assert_success
    echo "$export_content"
    assert_grep "SIGN_HMAC" "$export_content"

    echo "All logging tests passed"
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
run_test test_tls_certificates
run_test test_password_derivation
run_test test_wrapped_backup
run_test test_ssh_user_certificates
run_test test_ssh_host_certificates
run_test test_logging_commands

echo "All tests passed successfully!"
