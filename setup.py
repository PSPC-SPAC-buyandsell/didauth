import os
from setuptools import setup


pkg_name = 'didauth'
version = '0.0.1'

setup(
    name=pkg_name,
    packages=[
        pkg_name,
        '{}.proto'.format(pkg_name)
    ],
    version=version,
    description='DID authentication',
    license='MIT',
    author='PSPS-SPAC',
    author_email='',
    url='https://github.com/cywolf/{}'.format(pkg_name),
    download_url='https://github.com/cywolf/{}/archive/{}.tar.gz'.format(pkg_name, version),
    keywords=['verified-organizations-network', 'VON', 'SRI', 'DID', 'TheOrgBook', 'Hyperledger', 'Indy', 'HTTP'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: MIT',
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='>=3.6',
    install_requires=[
        'aiohttp',
        'base58',
        'multidict',
        'pynacl',
        'requests',
        'rsa',
        'secp256k1',
    ],
)
