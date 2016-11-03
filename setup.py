from setuptools import setup, find_packages

setup(
    name='pattern-matcher',
    version="1.0.0",
    packages=find_packages(),
    description='Match STIX content against STIX patterns',
    install_requires=[
        "six",
        "python-dateutil",
        "antlr4-python2-runtime>=4.5.3"
    ],
    tests_require=[
        "pytest>=2.9.2"
    ]
)
