from setuptools import setup, find_packages

setup(
    name="stab",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "typer>=0.12.0",
        "rich>=13.0.0",
        "httpx>=0.28.0",
        "dnspython>=2.6.0",
        "boto3>=1.34.0",
    ],
    entry_points={
        "console_scripts": [
            "stab=stab.cli:main",
        ],
    },
)
