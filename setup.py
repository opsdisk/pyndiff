import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyndiff",
    version="1.0.0",
    author="Brennon Thomas",
    author_email="info@opsdisk.com",
    description="Generate human-readable ndiff output when comparing 2 Nmap XML scan files.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rackerlabs/pyndiff",
    packages=setuptools.find_packages(),
    install_requires=[
        "xmljson>=0.2.0",
    ],
    python_requires=">=3.6",
    # fmt: off
    entry_points={
        "console_scripts": [
            "pyndiff = pyndiff.__main__:main"
        ]
    },
    # fmt: off
    license="License is Apache License Version 2.0",
    keywords="python Nmap ndiff xml compare scans",
)
