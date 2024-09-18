#!/bin/bash
CMD="hsm-secrets --mock=mock.pickle"

echo "This script is an example of how to set up a new YubiHSM2 cluster with hsm-secrets."
echo "By default, it uses '--mock=mock.pickle' to avoid needing physical devices, but you can remove"
echo "that flag and adapt the script to set up your real devices."
echo ""
echo "Press Enter to continue or Ctrl+C to abort"
read
rm -f mock.pickle
rm -f hsm-logs.sqlite

function phase_msg() {
    echo -e "\n ======================== NEXT PHASE: $1 ======================== \n"
}

phase_msg "Reset all devices to factory defaults"
$CMD hsm reset --alldevs

phase_msg "Apply log audit settings to all devices"
$CMD log apply-settings --alldevs

phase_msg "Install wrap key on all devices"
$CMD hsm backup make-key

phase_msg "Create keys on master device"
$CMD hsm objects create-missing --keys-only
phase_msg "Fetch and clear log (to avoid blocking)"
$CMD --auth-default-admin log fetch --clear hsm-logs.sqlite

phase_msg "Create certificates on master device"
$CMD hsm objects create-missing --certs-only

phase_msg "Fetch and clear log again"
$CMD --auth-default-admin log fetch --alldevs --clear hsm-logs.sqlite

phase_msg "Sanity check: verify fetched logs"
$CMD log verify-all hsm-logs.sqlite --alldevs

phase_msg "Create user auth keys on master device"
echo "(Here you would use YubiKey Manager to reset HSM auth slot and then '$CMD user add-yubikey <username>' to add each user)"
# ykman config usb --enable HSMAUTH
# ykman hsmauth reset
# $CMD user add-yubikey user_john.doe
# $CMD user add-yubikey user_alice.smith

phase_msg "Create service accounts on master device"
$CMD user add-service svc_log-audit svc_attestation svc_nac

phase_msg "Create shared super admin key on master device"
$CMD hsm admin sharing-ceremony -n 5 -t 3 -b

phase_msg "Fetch and clear log again"
$CMD --auth-default-admin log fetch --alldevs --clear hsm-logs.sqlite

phase_msg "Export backup from master device"
$CMD hsm backup export

phase_msg "Fetch and clear log again"
$CMD --auth-default-admin log fetch --alldevs --clear hsm-logs.sqlite

phase_msg "Import backup to the other devices"
$CMD --hsmserial 27600136 hsm backup import yubihsm2-device-27600135-wrapped-backup.tar.gz
$CMD --hsmserial 27600137 hsm backup import yubihsm2-device-27600135-wrapped-backup.tar.gz

phase_msg "Fetch and clear log again"
$CMD --auth-default-admin log fetch --alldevs --clear hsm-logs.sqlite

phase_msg "See that all devices are fully configured and in sync"
$CMD --auth-default-admin hsm compare --alldevs

phase_msg "Disable default admin password from all devices"
$CMD hsm admin default-disable --alldevs
