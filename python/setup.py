"""Setup script for pygosqlx - Python bindings for GoSQLX SQL parser."""

import os
from setuptools import setup, find_packages

long_description = ""
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
if os.path.exists(readme_path):
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="pygosqlx",
    version="0.1.0",
    description="Python bindings for GoSQLX - High-performance SQL parser",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="GoSQLX Contributors",
    url="https://github.com/ajitpratap0/GoSQLX",
    packages=find_packages(),
    package_data={"pygosqlx": ["lib/*", "py.typed"]},
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Database",
        "Topic :: Software Development :: Libraries",
    ],
)
