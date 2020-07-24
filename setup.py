# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='yarachecker',
    # note to self: always change this in config as well.
    version='1.0.0',
    description='A helper utility for processing YARA results, as used by IDAscope.',
    long_description_content_type="text/markdown",
    long_description=long_description,
    author='Daniel Plohmann',
    author_email='daniel.plohmann@mailbox.org',
    url='https://github.com/danielplohmann/yarachecker',
    license="BSD 2-Clause",
    packages=find_packages(exclude=('tests', 'docs')),
    install_requires=[
        'yara-python'
    ],
    data_files=[
        ('', ['LICENSE']),
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
