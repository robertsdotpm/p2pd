# Python version 3.5 and up.

from setuptools import setup, find_packages
from codecs import open
from os import path


here = path.abspath(path.dirname(__file__))
install_reqs = None
with open('requirements.txt') as f:
    install_reqs = f.read().splitlines()

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    version='2.0.0',
    name='p2pd',
    description='Asynchronous P2P networking library and service',
    keywords=('NAT traversal, TCP hole punching, simultaneous open, UPnP, STUN, TURN, SIP, DHCP, add IP to interface, NATPMP, P2P, Peer-to-peer networking library, python'),
    long_description=long_description,
    url='http://github.com/robertsdotpm/p2pd',
    author='Matthew Roberts',
    author_email='matthew@roberts.pm',
    license='public domain',
    package_dir={"": "."},
    packages=find_packages(exclude=('tests', 'docs')),
    install_requires=install_reqs,
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3'
    ],
)