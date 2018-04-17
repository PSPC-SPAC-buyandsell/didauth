import os
from setuptools import setup


pkg_name = 'did-auth'
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
    keywords=['VON', 'SRI', 'DID', 'TheOrgBook', 'hyperledger', 'indy'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'License :: OSI Approved :: MIT',
        'Programming Language :: Python :: 3.5',
    ],
    python_requires='>=3.5',
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
