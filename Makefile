.PHONY: setup install clean distclean package

# Configurable paths and settings
VENV := _venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
MODULE := hsm_secrets

DEPS_SRC := ""
PY_SRC := $(wildcard *.py) $(wildcard $(MODULE)/*.py) $(wildcard $(MODULE)/**/*.py)  #$(DEPS_SRC)
TARGET_BINS := $(VENV)/bin/hsm-secrets

$(TARGET_BINS): $(VENV) $(PY_SRC) $(VENV)/bin/mypy
	@echo "Verifying with mypy..."
	$(VENV)/bin/mypy $(MODULE) --ignore-missing-imports
	@echo "Installing the application..."
	$(PIP) install -e .
	@echo ""
	@echo "-- Done. You can now run the application with: --"
	echo "$(TARGET_BINS)"

$(VENV)/bin/mypy: $(VENV)
	@$(PIP) install mypy==1.9.0
	@touch $@

install: $(TARGET_BINS)

package: $(TARGET_BINS)
	@echo "Packaging the application..."
	@$(PYTHON) -m build --sdist

$(VENV): requirements.txt
	@echo "Setting up virtual environment..."
	python3 -m venv $(VENV)
	$(PIP) install -U pip
	$(PIP) install -r requirements.txt
	$(PIP) install build
	@touch $(VENV)

clean:
	@echo "Cleaning up build and Python file artifacts..."
	@rm -rf $(VENV)
	@rm -rf deps build dist *.egg-info dist_deb
	@find . -type f -name '*.pyc' -delete
	@find . -type d -name '__pycache__' -delete
