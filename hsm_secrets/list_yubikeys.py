"""
YubiKey listing and HSMauth status checking functionality.
"""

import click
import ykman.device
import ykman.scripting
from yubikit.hsmauth import HsmAuthSession
import yubikit.core

from hsm_secrets.utils import cli_info, cli_warn


@click.command('list-yubikeys', short_help='List all connected YubiKeys and their HSMauth status.')
def cmd_list_yubikeys():
    """List all YubiKeys connected to this computer and show if HSMauth is enabled on each."""

    devices = ykman.device.list_all_devices()

    if not devices:
        cli_info("No YubiKeys found.")
        return

    cli_info(f"Found {len(devices)} YubiKey(s):")
    cli_info("")

    for i, (yk_dev, yk_info) in enumerate(devices, 1):
        try:
            # Create scripting device to get more info
            yk = ykman.scripting.ScriptingDevice(yk_dev, yk_info)

            # Basic device info
            serial = yk_info.serial if yk_info.serial else "unknown"
            form_factor = yk_info.form_factor
            version = yk_info.version if hasattr(yk_info, 'version') else "unknown"

            cli_info(f"{i}. YubiKey {serial}")
            cli_info(f"   Form factor: {form_factor}")
            cli_info(f"   Version: {version}")

            # Check for HSMauth support and credentials
            hsmauth_status = "Not available"
            hsmauth_credentials = []

            try:
                sc = yk.smart_card()
                try:
                    hsmauth_session = HsmAuthSession(connection=sc)
                    credentials = list(hsmauth_session.list_credentials())

                    if credentials:
                        hsmauth_status = f"Enabled ({len(credentials)} credential(s))"
                        hsmauth_credentials = [(cred.label, cred.algorithm) for cred in credentials]
                    else:
                        hsmauth_status = "Enabled (no credentials)"

                except yubikit.core.ApplicationNotAvailableError:
                    hsmauth_status = "Not available"
                except yubikit.core.NotSupportedError:
                    hsmauth_status = "Not supported"
                finally:
                    sc.close()

            except Exception as e:
                hsmauth_status = f"Error checking: {str(e)}"

            # Display HSMauth status
            if hsmauth_status.startswith("Enabled"):
                status_colored = click.style(hsmauth_status, fg='green')
            elif hsmauth_status == "Not available":
                status_colored = click.style(hsmauth_status, fg='yellow')
            else:
                status_colored = click.style(hsmauth_status, fg='red')

            cli_info(f"   HSMauth: {status_colored}")

            # List credentials if any
            if hsmauth_credentials:
                cli_info("   HSMauth credentials:")
                for label, algorithm in hsmauth_credentials:
                    cli_info(f"     - {label} (Algorithm: {algorithm})")

            cli_info("")  # Empty line between devices

        except Exception as e:
            cli_warn(f"Error reading YubiKey {serial}: {str(e)}")
            cli_info("")
