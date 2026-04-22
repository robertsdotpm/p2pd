# Retained for tools that do not yet read pyproject.toml.
from setuptools import setup, find_packages
from os import path


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

install_reqs = [
    "aionetiface>=0.0.15",
    "namebump>=0.0.8",
    "sidewire>=0.1.1",
    "ecdsa>=0.18",
]
setup(
    version="4.0.1",
    name="p2pd",
    description="Asynchronous P2P networking library and service",
    keywords=(
        "NAT traversal, TCP hole punching, simultaneous open, UPnP, STUN, TURN, SIP, DHCP, add IP to interface, NATPMP, P2P, Peer-to-peer networking library, python"
    ),
    long_description_content_type="text/markdown",
    long_description=long_description,
    url="http://github.com/robertsdotpm/p2pd",
    author="Matthew Roberts",
    author_email="matthew@roberts.pm",
    license="public domain",
    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=("tests", "docs")),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=install_reqs,
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
)
