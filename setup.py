from setuptools import setup

setup(
    name='vmforensics',
    version='0.1.0',
    description='Utility to perform whois lookup during VM forensics',
    url='https://github.com/jayakumar/vmforensics',
    author='Jayakumar M',
    author_email='jai6684@yahoo.com',
    license='Apache License 2.0',
    packages=['whoislookup'],

    install_requires=[
        'ipwhois==1.1.0'
    ],

    entry_points={
            'console_scripts': ['whoislookup=whoislookup.whoislookup:main'],

        },

    classifiers=[
        'Development Status :: Beta',
        'Intended Audience :: Information security',
        'License :: OSI Approved :: Apache License 2.0',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
