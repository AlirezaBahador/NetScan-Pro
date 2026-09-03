from setuptools import setup, find_packages

setup(
    name="netscan-pro",
    version="1.2.0",
    description="Async TCP/UDP network scanner with banner grabbing and OS fingerprinting.",
    author="Alireza",
    packages=find_packages(exclude=("tests",)),
    install_requires=[
        "rich>=13.7.0",
        "PyYAML>=6.0.1",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "netscan=netscan.cli:main",
        ],
    },
)
