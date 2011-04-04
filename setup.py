#!/usr/bin/env python

from setuptools import setup

setup(
    name = 'oauth-client',
    version = '0.1',
    packages = ['oauth_client', 'oauth_client.adapter'],
    
    author = 'Lann Martin',
    author_email = 'oauth-client@lannbox.com',
    description = 'client library for OAuth 1.0',
    license = 'MIT',
    url = 'http://github.com/lann/python-oauth-client',

    test_suite = 'tests',
    tests_require = 'mock',
    )
