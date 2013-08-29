#!/usr/bin/python -tt

#Make it a bit more like python3:
from __future__ import absolute_import
from __future__ import print_function

import coverage
import sys
import unittest


def main():
    major, minor, micro, releaselevel, serial = sys.version_info

    if major == 2 and minor < 7:
        print("In order to run tests you need at least Python 2.7")
        sys.exit(1)

    if major == 3:
        print("Tests were not tested on Python 3.X, use at your own risk")
        sys.exit(1)

    #Perform coverage analisys:
    cov = coverage.coverage()

    cov.start()
    #Discover the test and execute them:
    loader = unittest.TestLoader()
    tests = loader.discover('.')
    testRunner = unittest.runner.TextTestRunner(descriptions=True, verbosity=1)
    testRunner.run(tests)
    cov.stop()

    cov.html_report()

if __name__ == '__main__':
    main()
