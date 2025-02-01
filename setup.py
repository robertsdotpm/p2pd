# Python version 3.5 and up.
from setuptools import setup, find_packages
from codecs import open
from os import path
import sys


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

install_reqs = ["ntplib", "xmltodict", "ecdsa"]
if (sys.version_info >= (3, 6)) or sys.platform != "win32":
    install_reqs += ["fasteners"]

if sys.platform != "win32":
    install_reqs += ["netifaces"]
    if sys.platform != "darwin":
        install_reqs += ["pyroute2"]
else:
    install_reqs += ["winregistry"]

setup(
    version='3.1.2',
    name='p2pd',
    description='Asynchronous P2P networking library and service',
    keywords=('NAT traversal, TCP hole punching, simultaneous open, UPnP, STUN, TURN, SIP, DHCP, add IP to interface, NATPMP, P2P, Peer-to-peer networking library, python'),
    long_description_content_type="text/markdown",
    long_description=long_description,
    url='http://github.com/robertsdotpm/p2pd',
    author='Matthew Roberts',
    author_email='matthew@roberts.pm',
    license='public domain',
    package_dir={"": "."},
    packages=find_packages(exclude=('tests', 'docs')),
    package_data={'p2pd': ['scripts/kvs_schema.sqlite3']},
    include_package_data=True,
    install_requires=install_reqs,
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3'
    ],
)
