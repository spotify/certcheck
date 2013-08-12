#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2013 Spotify AB

try:
    from spotify.build import setup
except ImportError:
    from setuptools import setup

setup(name='spotify-certcheck',
      version='1',
      author=u'Pawel Rozlach',
      author_email='prozlach@spotify.com',
      url='https://wiki.spotify.net/wiki/Python_packaging_policy',
      description='Simplified certificate check',
      packages=['spotify_certcheck'],
      scripts=['bin/certcheck'])
