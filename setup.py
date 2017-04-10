#!/usr/bin/env python
# coding=utf-8

from setuptools import setup


package_name = 'beacon'
filename = package_name + '.py'


def get_version():
    import ast

    with open(filename) as input_file:
        for line in input_file:
            if line.startswith('__version__'):
                return ast.parse(line).body[0].value.s


def get_long_description():
    try:
        with open('README.md', 'r') as f:
            return f.read()
    except IOError:
        return ''


setup(
    name=package_name,
    version=get_version(),
    author='FelixEli',
    author_email='f.eli.x.lopez.aguirre@gmail.com',
    description='utils beacon scan',
    url='https://github.com/gatoDev/beaconscan',
    long_description=get_long_description(),
    py_modules=[package_name],
    install_requires=[
          'markdown',
      ],
    entry_points={
        'console_scripts': [
            'beacon = beacon:main'
        ]
    },
    license='License :: OSI Approved :: MIT License',
)
