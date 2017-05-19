from setuptools import setup, find_packages

setup(
    name='stix2-matcher',
    version="0.1.0",
    packages=find_packages(),
    description='Match STIX content against STIX patterns',
    install_requires=[
        "antlr4-python2-runtime==4.7 ; python_version < '3'",
        "antlr4-python3-runtime==4.7 ; python_version >= '3'",
        'typing ; python_version<"3.5" and python_version>="3"',
        "enum34 ; python_version ~= '3.3.0'",
        "python-dateutil",
        "six",
        "stix2-patterns>=0.4.1",
    ],
    tests_require=[
        "pytest>=2.9.2"
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
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
