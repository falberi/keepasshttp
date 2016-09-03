# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='keepasshttp',
    version='0.0.1',
    description='Sample package for Python-Guide.org',
    long_description=readme,
    author='Fabien Alberi',
    author_email='fabien.alberi@gmail.com',
    url='https://github.com/falberi/keepasshttp',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)

