# YubiHSM2 Setup Workflow with hsm-secrets

This is checklist for setting up YubiHSM2 devices using the hsm-secrets tool.
The process should be performed in an airgapped environment for maximum security.

**TIP:** *You can try these steps withou actual HSM devices, by using `hsm-secrets --mock mock.pickle` instead of plain `hsm-secrets`*

## Initial Setup Workflow

1. `[ ]` Connect all YubiHSM2 devices to the airgapped computer.

2. `[ ]` Reset all devices to factory defaults.
   - Consult YubiHSM2 documentation for device-specific reset instructions.

3. `[ ]` Set a common wrap key on all devices:
   ```
   hsm-secrets hsm backup make-key
   ```

4. `[ ]` Host a Secret Sharing Ceremony to add a super admin key:
   ```
   hsm-secrets hsm admin sharing-ceremony
   ```
   - Follow the prompts to set up the number of shares and threshold.

5. `[ ]` Add YubiKey auth user keys to the master device:
   ```
   hsm-secrets user add-yubikey <user_label>
   ```
   - User will need to connect their YubiKey and follow instructions.
   - Repeat for each user key

6. `[ ]` Add service accounts to master device:
   ```
   hsm-secrets user add-service --all
   ```

7. `[ ]` Generate keys and certificates on the master device:
   ```
   hsm-secrets hsm objects create-missing
   ```

8. `[ ]` Apply audit logging settings to devices:
   ```
   hsm-secrets log apply-settings --alldevs
   ```

9. `[ ]` Verify all configured objects are present on the master device:
   ```
   hsm-secrets hsm compare
   ```

10. `[ ]` Create a (wrapped) backup of the master device:
   ```
   hsm-secrets hsm backup export
   ```

11. `[ ]` Restore the backup to other devices (for HA):
    ```
    hsm-secrets --hsmserial <device serial> hsm backup import <backup_file>
    ```
    - Repeat for each additional device.

12. `[ ]` Verify all keys are present on all devices:
    ```
    hsm-secrets hsm compare --alldevs
    ```

13. `[ ]` Remove the default admin key from all devices:
    ```
    hsm-secrets hsm admin default-disable --alldevs
    ```

## Post-Setup Verification

After completing the setup, perform these additional checks:

- `[ ]` Test authentication using YubiKeys for each user.
- `[ ]` Perform a test operation (e.g., signing a certificate) to ensure functionality.
