# YubiHSM2 Setup Workflow with hsm-secrets

This is checklist for setting up YubiHSM2 devices using the hsm-secrets tool.
The process should be performed in an airgapped environment for maximum security.

## Initial Setup Workflow

1. `[ ]` Connect all YubiHSM2 devices to the airgapped computer.

2. `[ ]` Reset all devices to factory defaults.
   - Consult YubiHSM2 documentation for device-specific reset instructions.

3. `[ ]` Set a common wrap key on all devices:
   ```
   hsm-secrets hsm make-wrap-key
   ```

4. `[ ]` Host a Secret Sharing Ceremony to add a super admin key:
   ```
   hsm-secrets hsm admin-sharing-ceremony
   ```
   - Follow the prompts to set up the number of shares and threshold.

5. `[ ]` Add user keys (YubiKey auth) to the master device:
   ```
   hsm-secrets user add-yubikey --label <user_label>
   ```
   - User will need to connect their YubiKey and follow instructions.
   - Repeat for each user key.

6. `[ ]` Generate keys on the master device:
   ```
   hsm-secrets hsm compare --create
   ```

7. `[ ]` Create certificates from the generated keys:
   ```
   hsm-secrets x509 create --all
   ```

8. `[ ]` Verify all configured objects are present on the master device:
   ```
   hsm-secrets hsm compare
   ```

9. `[ ]` Create a (wrapped) backup of the master device:
   ```
   hsm-secrets hsm backup
   ```

10. `[ ]` Restore the backup to other devices (for HA):
    ```
    hsm-secrets hsm restore <backup_file>
    ```
    - Repeat for each additional device.

11. `[ ]` Verify all keys are present on all devices:
    ```
    hsm-secrets hsm compare --alldevs
    ```

12. `[ ]` Remove the default admin key from all devices:
    ```
    hsm-secrets hsm default-admin-disable --alldevs
    ```

## Post-Setup Verification

After completing the setup, perform these additional checks:

- `[ ]` Test authentication using YubiKeys for each user.
- `[ ]` Perform a test operation (e.g., signing a certificate) to ensure functionality.
