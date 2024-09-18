from setuptools import setup, find_packages
from setuptools.command.install import install
import subprocess
import sys


setup(
    name='hsm_secrets',
    version='0.0.1',
    packages=find_packages(),
    include_package_data=True,

    install_requires=[],
    package_data={},

    entry_points='''
        [console_scripts]
        hsm-secrets=hsm_secrets.main:cli
    ''',
)
