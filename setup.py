from setuptools import find_packages, setup

setup(
    name='stix2-matcher',
    version='1.0.0',
    packages=find_packages(),
    description='Match STIX content against STIX patterns',
    install_requires=[
        'python-dateutil',
        'six',
        'stix2-patterns>=1.0.0',
        'typing ; python_version < "3.5" and python_version >= "3"',
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
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
