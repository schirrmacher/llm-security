from setuptools import setup, find_packages

setup(
    name="sak",
    version="0.1",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "sak = security_army_knife.cli:main",
        ],
    },
)
