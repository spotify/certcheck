#! /usr/bin/env python

from setuptools import setup

setup(name='certcheck',
      version='1',
      author=u'Pawel Rozlach',
      author_email='prozlach@spotify.com',
      description='Simplified certificate check',
      packages=['certcheck'],
      scripts=['bin/certcheck.py'])
