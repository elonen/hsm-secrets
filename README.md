# Secret Management tool for HSM operations

This package is a set of internal tools for YubiHSM2 operations,
meant to be installed locally using a Python virtual environment (`_venv`).

## Installation

1. Clone the repository to your local machine.
2. Run `make install` to set up the venv and install the package there.

## Usage

1. Clone the repository
2. Run `make` to set up the venv and install the package there.
3. Link the command to your shell environment. E.g. `rm -f ~/bin/hsm-secrets; ln -s $(pwd)/_venv/bin/hsm-secrets ~/bin/`

### Upgrade

```
git pull
make clean
make
```
