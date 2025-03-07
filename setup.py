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
    install_requires=[
        "black==24.4.0",
        "fastembed==0.2.7",
        "mistralai==1.0.1",
        "llama-index-core==0.10.55",
        "llama-index-llms-mistralai==0.1.17",
        "llama-index-llms-gemini==0.1.11",
        "llama-index==0.10.55",
        "pandas==2.2.2",
        "pytest==8.1.1",
        "networkx==3.3",
    ],
)
