#!/bin/bash
set -e

TEMPDIR=$(mktemp -d /tmp/hsm-secret-test.XXXXXX)
[[ $TEMPDIR =~ ^/tmp/hsm-secret-test ]] || { echo "Error: Invalid temp directory"; exit 1; }

# Start mock server for certificate uploads and CRL requests
echo "Starting mock server..."
_venv/bin/python test-mock-server.py 8693 &
MOCK_SERVER_PID=$!
trap "kill $MOCK_SERVER_PID 2>/dev/null || true; rm -rf $TEMPDIR" EXIT

# Give server time to start
sleep 1

cp hsm-conf.yml $TEMPDIR/
# Replace CRL URL with mock server endpoint to avoid external HTTP requests during testing
sed 's|http://crl.example.com|http://localhost:8693/mock-crl|g' $TEMPDIR/hsm-conf.yml > $TEMPDIR/hsm-conf-temp.yml
mv $TEMPDIR/hsm-conf-temp.yml $TEMPDIR/hsm-conf.yml
MOCKDB="$TEMPDIR/mock.pickle"
#CMD="./_venv/bin/hsm-secrets -c $TEMPDIR/hsm-conf.yml --mock $MOCKDB"
CURDIR=$(realpath $(dirname $0))
CMD="$CURDIR/_venv/bin/coverage run --parallel-mode --source=hsm_secrets $CURDIR/_venv/bin/hsm-secrets -c $TEMPDIR/hsm-conf.yml --mock $MOCKDB"


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
    $CMD "$@" 2>&1
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
    local output=$(run_cmd -q hsm objects create-missing)
    assert_success
    #echo "$output"
    assert_not_grep "Cert errors" "$output"
    assert_not_grep "Cert warnings" "$output"

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

    run_cmd -q hsm backup make-key
    assert_success
}

# ------------------ test cases -------------------------

test_pytest() {
    $CURDIR/_venv/bin/pip install pytest
    $CURDIR/_venv/bin/pytest --cov=hsm_secrets --cov-append --cov-report='' -v hsm_secrets
}

test_mypy() {
    echo "Running MyPy type checks..."
    $CURDIR/_venv/bin/pip install mypy
    $CURDIR/_venv/bin/mypy hsm_secrets --ignore-missing-imports
    assert_success
}

test_fresh_device() {
    local count=$(run_cmd -q hsm objects list | grep -c '^0x')
    [ "$count" -eq 1 ] || { echo "Expected 1 object, but found $count"; return 1; }
}

test_create_all() {
    setup

    # Run simplified secret sharing command
    expect << EOF
        $EXPECT_PREAMBLE
        spawn sh -c "$CMD hsm admin sharing-ceremony --skip-ceremony -n 3 -t 2 2>&1"
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

    local output=$(run_cmd -q hsm compare)
    assert_success
    echo "$output"
    #local count=$(run_cmd -q hsm compare | grep -c '\[x\]')
    local count=$(grep -c '\[x\]' <<< "$output")
    [ "$count" -eq 42 ] || { echo "Expected 42 objects, but found $count"; return 1; }

    # Remove default admin key
    run_cmd hsm admin default-disable
    assert_success
    local count=$(run_cmd -q hsm compare | grep -c '\[x\]')
    assert_success
    [ "$count" -eq 41 ] || { echo "Expected 41 objects, but found $count"; return 1; }

    # Try to add it back (with HSM, this would actually require shared secret reconstruction ceremony, but mocking doesn't really auth)
    expect << EOF
        $EXPECT_PREAMBLE
        spawn sh -c "$CMD -q hsm admin default-enable --use-backup-secret 2>&1"
        expect {
            "Is the backup secret hex" { sleep 0.1; send "n\r"; exp_continue }
            "Backup secret" { sleep 0.1; send "passw123\r"; exp_continue }
            timeout { handle_timeout }
            eof {}
        }
        $EXPECT_POSTAMBLE
EOF
    assert_success
}


test_attest() {
    setup
    local output=$(run_cmd hsm attest 0x0110)
    assert_success
    echo "$output"
    assert_grep "BEGIN CERTIFICATE" "$output"
}

test_tls_certificates() {
    setup
    run_cmd -q x509 cert get --all | openssl x509 -text -noout
    assert_success

    for CERT in cert_tls-t1-rsa3072  cert_tls-t1-ed25519_ed25519-root  cert_tls-t1-ecp384_ecp384-root; do
        # Check that intermediate's CRL distribution point is set to root-signed one
        local intermediate_cert=$(run_cmd -q x509 cert get $CERT | openssl x509 -in /dev/stdin -text -noout)
        assert_success
        echo "$intermediate_cert"
        assert_grep "URI:http.*/root-a1-.*crl" "$intermediate_cert"
    done

    for KEYTYPE in ed25519 ecp256 ecp384 rsa3072; do
        KEYBITS=$(echo $KEYTYPE | sed -E 's/[^0-9]//g')

        # Generate a server (end-entity) certificate
        local output=$(run_cmd tls server-cert --out $TEMPDIR/www-example-com_$KEYTYPE.pem --common-name www.example.com --san-dns www.example.org --san-ip 192.168.0.1 --san-ip fd12:123::80 --keyfmt $KEYTYPE)
        assert_success
        echo "$output"
        assert_not_grep "Cert errors" "$output"
        assert_not_grep "Cert warnings" "$output"

        local output=$(openssl crl2pkcs7 -nocrl -certfile $TEMPDIR/www-example-com_$KEYTYPE.cer.pem | openssl pkcs7 -print_certs | openssl x509 -text -noout)
        assert_success
        echo "$output"
        assert_grep 'Subject.*CN.*=.*www.example.com.*L.*=.*Duckburg.*ST.*=.*Calisota.*C.*=.*US' "$output"
        assert_grep 'DNS.*www.example.org' "$output"
        assert_grep 'IP Address.*192.168.0.1' "$output"
        assert_grep 'IP Address.*FD12:123' "$output"
        assert_grep "Public.*$KEYBITS" "$output"
        assert_grep 'Signature.*ecdsa' "$output"

        [ -f $TEMPDIR/www-example-com_$KEYTYPE.key.pem ] || { echo "ERROR: Key not saved"; return 1; }
        [ -f $TEMPDIR/www-example-com_$KEYTYPE.csr.pem ] || { echo "ERROR: CSR not saved"; return 1; }
        [ -f $TEMPDIR/www-example-com_$KEYTYPE.chain.pem ] || { echo "ERROR: Chain bundle not saved"; return 1; }
    done
}

test_tls_sign_command() {
    setup

    # Generate a CSR
    openssl req -new -newkey rsa:2048 -nodes -keyout $TEMPDIR/test.key -out $TEMPDIR/test.csr -subj "/CN=csrtest.example.com"

    # Sign the CSR using the TLS 'sign' command
    local output=$(run_cmd tls sign $TEMPDIR/test.csr --ca 0x0211 --out $TEMPDIR/test.crt)
    assert_success
    echo "$output"

    # Verify the signed certificate
    local cert_output=$(openssl x509 -in $TEMPDIR/test.crt -text -noout)
    assert_success
    echo "$cert_output"
    assert_grep "Subject:.*CN.*=.*csrtest.example.com" "$cert_output"
    assert_grep "Issuer:.*Duckburg" "$cert_output"
    assert_grep "CA.*FALSE" "$cert_output"
    assert_grep "X509v3 Key Usage: critical" "$cert_output"
    assert_grep "Digital Signature, Key Encipherment" "$cert_output"
    assert_grep "X509v3 Extended Key Usage:" "$cert_output"
    assert_grep "TLS Web Server Authentication" "$cert_output"
}

test_piv_user_certificate_key_type() {
    setup

    local output=$(run_cmd piv user-cert -u test.user@example.com --os-type windows --key-type rsa2048 --san "RFC822:test.user@example.com" --san "DIRECTORY:C=US,O=Organization,CN=test.user" --out $TEMPDIR/testuser-piv-key)
    assert_success
    echo "$output"
    assert_not_grep "Cert errors" "$output"
    assert_not_grep "Cert warnings" "$output"

    [ -f $TEMPDIR/testuser-piv-key.key.pem ] || { echo "ERROR: Key not saved"; return 1; }
    #[ -f $TEMPDIR/testuser-piv-key.csr.pem ] || { echo "ERROR: CSR not saved"; return 1; }
    [ -f $TEMPDIR/testuser-piv-key.cer.pem ] || { echo "ERROR: Certificate not saved"; return 1; }

    local cert_output=$(openssl x509 -in $TEMPDIR/testuser-piv-key.cer.pem -text -noout)
    assert_success
    echo "$cert_output"
    assert_grep "Subject:.*CN.*=.*test.user@example.com" "$cert_output"
    assert_grep "X509v3 Subject Alternative Name:" "$cert_output"
    assert_grep "test[.]user@example[.]com" "$cert_output"
    assert_grep "Organization.*test[.]user" "$cert_output"
    assert_grep "Key Usage: critical" "$cert_output"
    assert_grep "Extended Key Usage" "$cert_output"
    assert_grep "Smartcard" "$cert_output"
    assert_grep "Client Authentication" "$cert_output"
}

test_piv_user_certificate_csr() {
    setup

    # Generate a CSR
    openssl ecparam -genkey -name secp384r1 -out $TEMPDIR/testuser-csr.key.pem
    openssl req -new -key $TEMPDIR/testuser-csr.key.pem -nodes -keyout $TEMPDIR/testuser-csr.key.pem -out $TEMPDIR/testuser-csr.csr.pem -subj "/CN=test.user@example.com"

    local output=$(run_cmd piv user-cert -u test.user@example.com --os-type windows --csr $TEMPDIR/testuser-csr.csr.pem --san "RFC822:test.user@example.com" --san "DIRECTORY:C=US,O=Organization,CN=test.user" --out $TEMPDIR/testuser-piv-csr)
    assert_success
    echo "$output"
    assert_not_grep "Cert errors" "$output"
    assert_not_grep "Cert warnings" "$output"

    [ ! -f $TEMPDIR/testuser-piv-csr.key.pem ] || { echo "ERROR: Key should not be saved when using CSR"; return 1; }
    [ ! -f $TEMPDIR/testuser-piv-csr.csr.pem ] || { echo "ERROR: CSR should not be saved when using existing CSR"; return 1; }
    [ -f $TEMPDIR/testuser-piv-csr.cer.pem ] || { echo "ERROR: Certificate not saved"; return 1; }

    local cert_output=$(openssl x509 -in $TEMPDIR/testuser-piv-csr.cer.pem -text -noout)
    assert_success
    echo "$cert_output"
    assert_grep "Subject:.*CN.*=.*test.user@example.com" "$cert_output"
    assert_grep "X509v3 Subject Alternative Name:" "$cert_output"
    assert_grep "test[.]user@example[.]com" "$cert_output"
    assert_grep "Organization.*test[.]user" "$cert_output"
    assert_grep "Key Usage: critical" "$cert_output"
    assert_grep "Extended Key Usage" "$cert_output"
    assert_grep "Smartcard" "$cert_output"
    assert_grep "Client Authentication" "$cert_output"
}

test_piv_dc_certificate() {
    setup

    # Generate a CSR for the DC certificate
    openssl ecparam -genkey -name secp384r1 -out $TEMPDIR/dc.key.pem
    openssl req -new -key $TEMPDIR/dc.key.pem -out $TEMPDIR/dc.csr.pem -subj "/CN=dc01.example.com"

    local output=$(run_cmd piv sign-dc-cert $TEMPDIR/dc.csr.pem --san "DNS:dc01.example.com" --san "DNS:dc.example.com" --out $TEMPDIR/dc.cer.pem)
    assert_success
    echo "$output"
    assert_not_grep "Cert errors" "$output"
    assert_not_grep "Cert warnings" "$output"

    [ -f $TEMPDIR/dc.cer.pem ] || { echo "ERROR: Signed certificate not saved"; return 1; }

    local cert_output=$(openssl x509 -in $TEMPDIR/dc.cer.pem -text -noout)
    assert_success
    echo "$cert_output"
    assert_grep "Subject:.*CN.*=.*dc01.example.com" "$cert_output"
    assert_grep "X509v3 Subject Alternative Name:" "$cert_output"
    assert_grep "DNS:dc01.example.com" "$cert_output"
    assert_grep "DNS:dc.example.com" "$cert_output"
    assert_grep "Key Usage: critical" "$cert_output"
    assert_grep "Extended Key Usage:" "$cert_output"
    assert_grep "Signing KDC Response" "$cert_output"
    assert_grep "Microsoft Smartcard Login" "$cert_output"
    assert_grep "Server Authentication" "$cert_output"
    assert_grep "KDC" "$cert_output"
}


test_crl_commands() {
    setup

    # Try generating multiple CRLs first, with defaults
    cd "$TEMPDIR"
    run_cmd x509 crl init cert_tls-t1-ecp384_rsa3072-root cert_nac-n1-ecp256
    assert_success
    [ -f $TEMPDIR/tls-t1-ecp384.crl ] || { echo "ERROR: CRL file not created"; return 1; }
    [ -f $TEMPDIR/nac-n1-ecp256.crl ] || { echo "ERROR: CRL file not created"; return 1; }

    # Initialize a test CRL
    run_cmd x509 crl init --out $TEMPDIR/test.crl --period 30 0x0211
    assert_success
    [ -f $TEMPDIR/test.crl ] || { echo "ERROR: CRL file not created"; return 1; }

    # Verify the initial CRL with OpenSSL
    local initial_output=$(openssl crl -in $TEMPDIR/test.crl -text -noout)
    assert_success
    echo "$initial_output"
    assert_grep "Certificate Revocation List" "$initial_output"
    assert_grep "Issuer.*Duckburg" "$initial_output"
    assert_grep "Next Update:" "$initial_output"
    assert_grep "No Revoked Certificates" "$initial_output"

    # Update the CRL with a revoked certificate
    local revoke_date=$(date -u +"%Y-%m-%d")
    run_cmd x509 crl update $TEMPDIR/test.crl --ca 0x0211 --add "1000:$revoke_date:keyCompromise"
    assert_success

    # Verify the updated CRL
    local update_output=$(openssl crl -in $TEMPDIR/test.crl -text -noout)
    assert_success
    echo "$update_output"
    assert_grep "Certificate Revocation List" "$update_output"
    assert_grep "Serial Number: 03E8" "$update_output"
    assert_grep "Revocation Date:" "$update_output"
    assert_grep "Key Compromise" "$update_output"

    # Show CRL information
    local show_output=$(run_cmd x509 crl show $TEMPDIR/test.crl)
    assert_success
    echo "$show_output"
    assert_grep "CRL Issuer.*Duckburg," "$show_output"
    assert_grep "Number of revoked certificates: 1" "$show_output"
    assert_grep ".*0x3e8.*$revoke_date.*keyCompromise" "$show_output"

    # Update CRL to remove a certificate
    run_cmd x509 crl update $TEMPDIR/test.crl --ca 0x0211 --remove 1000
    assert_success

    # Verify the final CRL state
    local final_output=$(openssl crl -in $TEMPDIR/test.crl -text -noout)
    assert_success
    echo "$final_output"
    assert_grep "No Revoked Certificates" "$final_output"
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
    run_cmd -q hsm backup export --all --out $TEMPDIR/backup.tgz
    assert_success

    tar tvfz $TEMPDIR/backup.tgz | grep -q 'ASYMMETRIC_KEY' || { echo "ERROR: No asymmetric keys found in backup"; return 1; }
    tar tvfz $TEMPDIR/backup.tgz | grep -q 'OPAQUE' || { echo "ERROR: No certificates found in backup"; return 1; }

    run_cmd -q hsm objects delete --force 0x0210
    assert_success
    run_cmd -q hsm compare | grep -q '[ ].*0x0210' || { echo "ERROR: Key not deleted"; return 1; }
    assert_success

    run_cmd -q hsm backup import --force $TEMPDIR/backup.tgz
    assert_success
    run_cmd -q hsm compare | grep -q '[x].*0x0210' || { echo "ERROR: Key not restored"; return 1; }
    assert_success
}

test_ssh_user_certificates() {
    setup
    run_cmd ssh get-ca --all | ssh-keygen -l -f /dev/stdin
    assert_success

    # RSA key
    ssh-keygen -t rsa -b 2048 -f $TEMPDIR/testkey_rsa -N '' -C 'testkey'
    run_cmd ssh sign-user -u test.user --ca key_ssh-root-ca-rsa3072 -p users,admins $TEMPDIR/testkey_rsa.pub
    assert_success

    # ECDSA 256 key
    ssh-keygen -t ecdsa -b 256 -f $TEMPDIR/testkey_ecdsa -N '' -C 'testkey'
    run_cmd ssh sign-user -u test.user --ca key_ssh-root-ca-ecp384 -p users,admins $TEMPDIR/testkey_ecdsa.pub
    assert_success

    # ED25519 key
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

test_codesign_sign_osslsigncode_hash() {

    if ! which osslsigncode > /dev/null; then
        echo "osslsigncode not found, skipping test"
        return 0
    fi

    setup

    # Create a temporary directory for this test
    local test_dir=$(mktemp -d "$TEMPDIR/codesign_test.XXXXXX")

    # Write a m inimal 'tiny.exe' for testing
    echo "H4sIAH/x+VYAA/ONmsDAzMDAwALE//8zMOxggAAHBsJgAxDzye/iY9jCeVZxB6PPWcWQjMxihYKi/PSixFyF5MS8vPwShaRUhaLSPIXMPAUX/2CF3PyUVD1eXi4VqBk/dYtu7vWR6YLhWV2FXXvAdAqYDspMzgCJw+wMcGVg8GFkZMjf6+oKE3vAwMzIzcjBwMCE5DgBKFaA+gbEZoL4k4EBQYPlofog0gIQtXAaTg0o0CtJrShhgLob6hcU/zKAvZJAqrlZWhGHKXbcKBiyAAD3yoGLAAQAAA==" | base64 -d | gzip -d > "$test_dir/tiny.exe"

    # Extract hash to be signed from tiny.exe
    osslsigncode extract-data -h sha256 -in "$test_dir/tiny.exe" -out "$test_dir/tiny.req"
    assert_success

    # Sign the request using the HSM
    run_cmd codesign sign-osslsigncode-hash "$test_dir/tiny.req"
    assert_success

    # Check if the signed file exists
    [ -f "$test_dir/tiny.signed.req" ] || { echo "ERROR: Signed file not created"; return 1; }

    # Get the full certificate chain from HSM
    run_cmd x509 cert get --bundle "$test_dir/bundle.pem" cert_codesign-cs1-rsa3072 cert_ca-root-a1-rsa3072
    assert_success

    # Create a CRL
    run_cmd x509 crl init -o "$test_dir/crl.pem"  cert_ca-root-a1-rsa3072
    assert_success

    # Attach the signature to the executable
    local attach_output=$(osslsigncode attach-signature -sigin "$test_dir/tiny.signed.req" -CAfile "$test_dir/bundle.pem" -CRLfile "$test_dir/crl.pem" -in "$test_dir/tiny.exe" -out "$test_dir/tiny.signed.exe")
    assert_success

    # Check the output of the attach-signature command
    echo "$attach_output"
    assert_grep "Signature successfully attached" "$attach_output"
    assert_grep "Succeeded" "$attach_output"

    # Verify the signed executable
    local verify_output=$(osslsigncode verify -in "$test_dir/tiny.signed.exe" -CAfile "$test_dir/bundle.pem"  -CRLfile "$test_dir/crl.pem")
    assert_success
    echo "$verify_output"
    assert_grep "Signature verification: ok" "$verify_output"

    echo "Codesign sign-osslsigncode-hash test passed successfully"
}

test_logging_commands() {
    local DB_PATH="$TEMPDIR/test_log.db"
    export HSM_PASSWORD="password123-not-really-set"

    # Test first fetch
    run_cmd --auth-password-id='svc_log-audit' log fetch "$DB_PATH"
    assert_success
    [ -f "$DB_PATH" ] || { echo "ERROR: Log database not created"; return 1; }

    # Apply audit settings
    local apply_output=$(run_cmd log apply-settings --force)
    assert_success
    assert_grep "settings applied" "$apply_output"

    setup   # Create some objects

    # Fetch again twice to log SET_LOG_INDEX due to --clear
    run_cmd --auth-password-id='svc_log-audit' log fetch "$DB_PATH" --clear
    assert_success
    run_cmd --auth-password-id='svc_log-audit' log fetch "$DB_PATH"
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

    run_cmd --auth-password-id='svc_log-audit' log fetch "$DB_PATH" -c
    assert_success
    run_cmd log verify-all "$DB_PATH"
    assert_success

    local export_content=$(run_cmd log export "$DB_PATH")
    assert_success
    echo "$export_content"
    assert_grep "SIGN_HMAC" "$export_content"

    echo "All logging tests passed"
}

test_tls_recreate_from_tls() {
    setup

    # Test against google.com, a well-known, stable HTTPS service
    local output=$(run_cmd tls recreate-from-tls https://google.com --out $TEMPDIR/google-csr.pem --keyfmt ecp384)
    assert_success
    echo "$output"

    # Verify output contains expected information
    assert_grep "Connecting to google.com:443" "$output"
    assert_grep "Retrieved certificate for:" "$output"
    assert_grep "Private key written to:" "$output"
    assert_grep "CSR written to:" "$output"
    assert_grep "To sign this CSR with your CA, run:" "$output"
    assert_grep "hsm-secrets tls sign" "$output"
    assert_grep "Certificate details extracted:" "$output"

    # Verify files were created
    [ -f $TEMPDIR/google-csr.pem ] || { echo "ERROR: CSR not saved"; return 1; }
    [ -f $TEMPDIR/google-csr.key.pem ] || { echo "ERROR: Key not saved"; return 1; }

    # Verify CSR content using OpenSSL
    local csr_output=$(openssl req -in $TEMPDIR/google-csr.pem -text -noout)
    assert_success
    echo "$csr_output"
    assert_grep "Subject.*google" "$csr_output"  # Should contain google in CN or subject
    assert_grep "Subject Alternative Name" "$csr_output"  # Should have SANs
    assert_grep "TLS Web Server Authentication" "$csr_output"  # Should have server auth EKU
    assert_grep "Digital Signature" "$csr_output"  # Should have correct key usage
    assert_grep "secp384r1" "$csr_output"  # Should use requested key format

    # Test tls:// URL scheme
    local output2=$(run_cmd tls recreate-from-tls tls://google.com:443 --out $TEMPDIR/google-tls-scheme.csr.pem)
    assert_success
    echo "$output2"
    assert_grep "Connecting to google.com:443" "$output2"

    # Test that both methods produce similar results (same CN at minimum)
    local csr1_subject=$(openssl req -in $TEMPDIR/google-csr.pem -subject -noout)
    local csr2_subject=$(openssl req -in $TEMPDIR/google-tls-scheme.csr.pem -subject -noout)
    # Both should have the same subject (though different keys)
    [ "$csr1_subject" = "$csr2_subject" ] || { echo "ERROR: tls:// and https:// schemes produced different subjects"; return 1; }

    # Test signing the generated CSR works
    local sign_output=$(run_cmd tls sign $TEMPDIR/google-csr.pem --out $TEMPDIR/google-signed.cer.pem)
    assert_success
    echo "$sign_output"
    assert_grep "Signed certificate saved" "$sign_output"

    # Verify signed certificate
    local cert_output=$(openssl x509 -in $TEMPDIR/google-signed.cer.pem -text -noout)
    assert_success
    assert_grep "Subject.*google" "$cert_output"
    assert_grep "TLS Web Server Authentication" "$cert_output"
    assert_grep "CA:FALSE" "$cert_output"
}

test_tls_resign_from_tls() {
    setup

    # Test resign-from-tls with Google's server
    local output=$(run_cmd tls resign-from-tls https://google.com --out $TEMPDIR/google-resigned.cer.pem)
    assert_success
    echo "$output"

    # Verify output contains expected information
    assert_grep "Connecting to google.com:443" "$output"
    assert_grep "Retrieved certificate from:" "$output"
    assert_grep "Extracted public key:" "$output"
    assert_grep "Signed certificate saved" "$output"
    assert_grep "Server certificate details copied:" "$output"
    assert_grep "Certificate ready - contains server's exact public key and subject" "$output"

    # Verify certificate file was created
    [ -f $TEMPDIR/google-resigned.cer.pem ] || { echo "ERROR: Resigned certificate not created"; return 1; }

    # Extract public key from original Google server
    openssl s_client -connect google.com:443 -servername google.com </dev/null 2>/dev/null | openssl x509 -pubkey -noout > $TEMPDIR/original-google-pubkey.pem
    assert_success

    # Extract public key from our HSM-signed certificate
    openssl x509 -in $TEMPDIR/google-resigned.cer.pem -pubkey -noout > $TEMPDIR/resigned-google-pubkey.pem
    assert_success

    # Verify public keys are identical
    diff $TEMPDIR/original-google-pubkey.pem $TEMPDIR/resigned-google-pubkey.pem
    assert_success
    echo "✅ Public keys match between original and resigned certificates"

    # Verify subject is preserved
    local original_subject=$(openssl s_client -connect google.com:443 -servername google.com </dev/null 2>/dev/null | openssl x509 -subject -noout)
    assert_success
    local resigned_subject=$(openssl x509 -in $TEMPDIR/google-resigned.cer.pem -subject -noout)
    assert_success

    [ "$original_subject" = "$resigned_subject" ] || { echo "ERROR: Subject changed from '$original_subject' to '$resigned_subject'"; return 1; }
    echo "✅ Subject preserved exactly"

    # Verify issuer changed (should be HSM CA, not Google's original issuer)
    local original_issuer=$(openssl s_client -connect google.com:443 -servername google.com </dev/null 2>/dev/null | openssl x509 -issuer -noout)
    assert_success
    local resigned_issuer=$(openssl x509 -in $TEMPDIR/google-resigned.cer.pem -issuer -noout)
    assert_success

    [ "$original_issuer" != "$resigned_issuer" ] || { echo "ERROR: Issuer should have changed but didn't"; return 1; }
    assert_grep "Example TLS Intermediate" "$resigned_issuer"
    echo "✅ Issuer correctly changed to HSM CA"

    # Verify certificate works for TLS server
    local cert_details=$(openssl x509 -in $TEMPDIR/google-resigned.cer.pem -text -noout)
    assert_success
    assert_grep "Subject.*google" "$cert_details"
    assert_grep "TLS Web Server Authentication" "$cert_details"
    assert_grep "CA:FALSE" "$cert_details"
    assert_grep "Subject Alternative Name" "$cert_details"
    assert_grep "DNS:.*google" "$cert_details"
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
    echo ""
    echo "🚧 ------------ run_test $1 ------------ 🚧"
    echo ""
    if $1; then
        echo "OK"
    else
        echo "FAILED"
        return 1
    fi
    rm -f $MOCKDB
}

# Reset previous coverage files before accumulating new data
$CURDIR/_venv/bin/pip install coverage pytest-cov
rm -f .coverage .coverage.*

echo "Running tests:"

run_test test_pytest
run_test test_mypy
run_test test_attest
run_test test_fresh_device
run_test test_create_all
run_test test_tls_certificates
run_test test_tls_sign_command
run_test test_tls_recreate_from_tls
run_test test_tls_resign_from_tls
run_test test_crl_commands
run_test test_password_derivation
run_test test_wrapped_backup
run_test test_ssh_user_certificates
run_test test_ssh_host_certificates
run_test test_codesign_sign_osslsigncode_hash
run_test test_piv_user_certificate_key_type
run_test test_piv_user_certificate_csr
run_test test_piv_dc_certificate
run_test test_logging_commands

echo "---"

echo "Running coverage report:"
$CURDIR/_venv/bin/coverage combine --append
$CURDIR/_venv/bin/coverage report
$CURDIR/_venv/bin/coverage html
$CURDIR/_venv/bin/coverage xml

echo "---"
echo "OK. All tests passed successfully!"
