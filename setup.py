import os
from setuptools import setup


pkg_name = 'didauth'
version = '1.2.2'

setup(
    name=pkg_name,
    packages=[
        pkg_name,
        '{}.algo'.format(pkg_name),
        '{}.ext'.format(pkg_name),
    ],
    version=version,
    description='DID authentication',
    license='MIT',
    author='PSPC-SPAC',
    author_email='',
    url='https://github.com/PSPC-SPAC-buyandsell/{}'.format(pkg_name),
    download_url='https://github.com/PSPC-SPAC-buyandsell/{}/archive/{}.tar.gz'.format(pkg_name, version),
    keywords=['verified-organizations-network', 'VON', 'SRI', 'DID', 'TheOrgBook', 'Hyperledger', 'Indy', 'HTTP'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: MIT',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='>=3.5.3',
    install_requires=[
        'base58',
        'multidict',
        'libnacl',
    ],
)
