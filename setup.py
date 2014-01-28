#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2013 Spotify AB
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

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
