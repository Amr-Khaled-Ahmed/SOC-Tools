from setuptools import setup, find_packages

setup(
    name="phishtinker",
    version="1.0.0",
    description="Local phishing email triage tool (PhishTool-style) with GUI and CLI",
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "full": ["requests", "oletools", "pypdf"],
    },
    entry_points={
        "console_scripts": [
            "phishtinker=phishtinker.__main__:main",
        ],
    },
)
