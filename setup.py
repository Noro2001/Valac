#!/usr/bin/env python3
"""
Setup script for Valac - Unified Security Scanner Suite
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="valac",
    version="1.0.0",
    description="Unified Security Scanner Suite - IP scanning, DNS resolution, subdomain enumeration, fuzzing, and CSV extraction",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Valac Security Team",
    author_email="",
    url="https://github.com/valac/valac",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    py_modules=["valac"],  # Include valac.py as a module
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "valac=valac:main",
        ],
    },
    keywords="security scanner vulnerability ip dns subdomain fuzzing penetration-testing",
    project_urls={
        "Documentation": "https://github.com/valac/valac/blob/main/README.md",
        "Source": "https://github.com/valac/valac",
        "Tracker": "https://github.com/valac/valac/issues",
    },
)

