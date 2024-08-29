from abc import ABC, abstractmethod
from typing import Sequence
from hsm_secrets.utils import cli_ui_msg, secure_display_secret
import click

class SecretSharingUIBase(ABC):
    """
    UI abstraction for secret sharing operations.
    This helps unit testing by allowing to mock the UI.
    """
    @abstractmethod
    def msg(self, msg: str):
        pass

    @abstractmethod
    def pause(self, msg: str):
        pass

    @abstractmethod
    def confirm_or_abort(self, msg: str):
        pass

    @abstractmethod
    def clear(self):
        pass

    @abstractmethod
    def prompt_name_and_password(self, share_num: int, existing_names: Sequence[str]) -> tuple[str, str|None]:
        pass

    @abstractmethod
    def display_share(self, share_num: int, share_str: str):
        pass

    @abstractmethod
    def display_backup_part(self, share_num: int, backup_part_str: str):
        pass

    @abstractmethod
    def prompt_password(self, message: str, share_num: int) -> str:
        pass

    @abstractmethod
    def prompt_share_str(self, message: str, share_num: int) -> str:
        pass

    @abstractmethod
    def prompt_backup_part_str(self, message: str, share_num: int) -> str:
        pass

    @abstractmethod
    def prompt_threshold(self) -> int:
        pass

# -----

class SecretSharingClickUI(SecretSharingUIBase):
    """
    UI implementation using Click for secret sharing ceremonies.
    """
    def msg(self, msg: str):
        cli_ui_msg(msg)

    def pause(self, msg: str):
        click.pause(msg)

    def confirm_or_abort(self, msg: str):
        click.confirm(msg, abort=True, err=True)

    def clear(self):
        click.clear()

    def prompt_name_and_password(self, share_num: int, existing_names: Sequence[str]) -> tuple[str, str|None]:
        name = click.prompt(f"Enter the name of custodian #{share_num}", err=True).strip() or f"#{share_num}"
        if name in existing_names:
            raise click.UsageError(f"Name '{name}' is already in use. Please enter a unique name.")

        if click.confirm(f"Password-protect share?", abort=False, err=True):
            pw = click.prompt("Custodian " + click.style(f"'{name}'", fg='green') + ", enter the password", hide_input=True, err=True).strip()
        else:
            pw = None
        cli_ui_msg("")
        return name, pw

    def display_share(self, share_num: int, share_str: str):
        secure_display_secret(share_str)

    def display_backup_part(self, share_num: int, backup_part_str: str):
        secure_display_secret(backup_part_str)

    def prompt_password(self, message: str, share_num: int) -> str:
        return click.prompt(message, hide_input=True, err=True)

    def prompt_share_str(self, message: str, share_num: int) -> str:
        return click.prompt(message, hide_input=True, err=True)

    def prompt_backup_part_str(self, message: str, share_num: int) -> str:
        return click.prompt(message, hide_input=True, err=True)

    def prompt_threshold(self) -> int:
        return click.prompt("How many shares are required to reconstruct the secret", type=int, err=True)

# -----

class SecretSharingMockUI(SecretSharingUIBase):
    """
    Mock UI implementation for testing secret sharing ceremonies.

    This simulates users writing down their shares and backup parts on paper,
    and entering them back into the program when prompted.
    """

    def __init__(self, threshold: int, test_names: Sequence[str], test_passwords: Sequence[str|None]) -> None:
        self.threshold = threshold
        self.test_names: dict[int, str] = {i+1: n for i, n in enumerate(test_names)}
        self.test_passwords: dict[int, str|None] = {i+1: p for i, p in enumerate(test_passwords)}
        self.test_share_strs: dict[int, str] = {}
        self.test_backup_part_strs: dict[int, str] = {}
        assert len(self.test_names) == len(self.test_passwords)

    def msg(self, msg: str):
        print("< MOCK msg():", msg)

    def pause(self, msg: str):
        pass

    def confirm_or_abort(self, msg: str):
        print("> MOCK confirm_or_abort():", msg, "-- answering YES")

    def clear(self):
        pass

    def prompt_name_and_password(self, share_num: int, existing_names: Sequence[str]) -> tuple[str, str|None]:
        print("> MOCK: ask for name and password -- answers:", self.test_names[share_num], self.test_passwords[share_num])
        return self.test_names[share_num], self.test_passwords[share_num]

    def display_share(self, share_num: int, share_str: str):
        print(f"< MOCK: display share #{share_num}:", share_str)
        self.test_share_strs[share_num] = share_str

    def display_backup_part(self, share_num: int, backup_part_str: str):
        print(f"< MOCK: display backup part #{share_num}:", backup_part_str)
        self.test_backup_part_strs[share_num] = backup_part_str

    def prompt_password(self, message: str, share_num: int) -> str:
        print(f"> MOCK: prompt for password for share #{share_num} -- message: '{message}', answering:", self.test_passwords[share_num])
        pw = self.test_passwords[share_num]
        assert pw is not None
        return pw

    def prompt_share_str(self, message: str, share_num: int) -> str:
        print(f"> MOCK: prompt for share #{share_num} -- message: '{message}', answering:", self.test_share_strs[share_num].replace(' ', '').replace('-', ' '))
        return self.test_share_strs[share_num]

    def prompt_backup_part_str(self, message: str, share_num: int) -> str:
        print(f"> MOCK: prompt for backup part #{share_num} -- message: '{message}', answering:", self.test_backup_part_strs[share_num].replace(' ', '').replace('-', ' '))
        return self.test_backup_part_strs[share_num]

    def prompt_threshold(self) -> int:
        print("> MOCK: prompt for threshold -- answering:", self.threshold)
        return self.threshold
