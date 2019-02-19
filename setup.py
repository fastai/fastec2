from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__)) + '/'

with open(path.join(here, 'README.md'), encoding='utf-8') as f: long_description = f.read()

setup(
    name='fastec2',
    version='1.0.0',
    description="AWS EC2 computer management for regular folks",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/fastai/fastec2',
    author='Jeremy Howard',
    classifiers=[
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],

    keywords='development',
    packages=["fastec2"],
    package_data={'fastec2': [ 'insttypes.txt', 'prices.csv' ]},
    entry_points={ 'console_scripts': [ 'fe2=fastec2:main'] },
    install_requires=[ 'boto3', 'awscli', 'fire', 'numpy', 'pandas', 'paramiko', 'pysftp' ],
)

