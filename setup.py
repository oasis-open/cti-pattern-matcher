from setuptools import setup, find_packages

setup(
    name='pattern-matcher',
    version="1.0.0",
    packages=find_packages(),
    description='Match STIX content against STIX patterns',
    install_requires=[
        "antlr4-python2-runtime==4.5.3 ; python_version < '3'",
        "antlr4-python3-runtime==4.5.3 ; python_version >= '3'",
        "enum34 ; python_version ~= '3.3.0'",
        "python-dateutil",
        "six",
    ],
    tests_require=[
        "pytest>=2.9.2"
    ]
)
