import setuptools


setuptools.setup(
    name='dns-fc',
    version='1.0',
    description='Simple dns forwarding and cache server',
    author='dimastark',
    author_email='dstarkdev@gmail.com',
    entry_points={
        'console_scripts': [
            'dns-fc = dnsfc.main:main',
        ]
    },
    packages=setuptools.find_packages(
        '.',
        exclude=[
            '*.tests', '*.tests.*', 'tests.*', 'tests',
        ],
    ),
    package_data={'': []},
    include_package_data=True,
    install_requires=[
        'setuptools',
    ],
    tests_require=['nose'],
    test_suite='nose.collector',
)
