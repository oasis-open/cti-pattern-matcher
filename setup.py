#!/usr/bin/env python
from codecs import open

from setuptools import find_packages, setup


def get_long_description():
    with open('README.rst') as f:
        return f.read()


setup(
    name='stix2-matcher',
    version='2.0.2',
    packages=find_packages(),
    long_description=get_long_description(),
    description='Match STIX content against STIX patterns',
    long_description_content_type='text/x-rst',
    install_requires=[
        'python-dateutil',
        'six',
        'stix2-patterns>=1.0.0',
    ],
    tests_require=[
        'pytest>=2.9.2'
    ],
    entry_points={
        'console_scripts': [
            'stix2-matcher = stix2matcher.matcher:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
