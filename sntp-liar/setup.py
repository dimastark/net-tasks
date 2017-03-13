import setuptools


setuptools.setup(
    name='sntp-liar',
    version='1.0',
    description='SNTP liar server',
    author='dimastark',
    author_email='dstarkdev@gmail.com',
    entry_points={
        'console_scripts': [
            'sntp-liar = sntp_liar.lsntp:main',
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
