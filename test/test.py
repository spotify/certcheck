#!/usr/bin/python -tt

#Make it a bit more like python3:
from __future__ import absolute_import
from __future__ import print_function

import coverage
import os
import subprocess
import sys
import unittest


def create_test_cert(days, path, is_der=False):
    openssl_cmd = ["/usr/bin/openssl", "req", "-x509", "-nodes",
                   "-newkey", "rsa:1024",
                   "-subj", "/C=SE/ST=Stockholm/L=Stockholm/CN=www.example.com"]

    openssl_cmd.extend(["-days", str(days)])
    openssl_cmd.extend(["-out", path])

    if is_der:
        openssl_cmd.extend(["-outform", "DER"])
        openssl_cmd.extend(["-keyout", path + ".key"])
    else:
        openssl_cmd.extend(["-keyout", path])

    child = subprocess.Popen(openssl_cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    child_stdout, child_stderr = child.communicate()
    if child.returncode != 0:
        print("Failed to execute opensssl command:\n\t{0}\n".format(' '.join(openssl_cmd)))
        print("Stdout+Stderr:\n{0}".format(child_stdout))
        sys.exit(1)
    else:
        print("Created test certificate {0}".format(os.path.basename(path)))


def main():
    major, minor, micro, releaselevel, serial = sys.version_info

    if major == 2 and minor < 7:
        print("In order to run tests you need at least Python 2.7")
        sys.exit(0)

    if major == 3:
        print("Tests were not tested on Python 3.X, use at your own risk")
        sys.exit(0)

    #Prepare the test certificate tree:
    script_dir = os.path.dirname(os.path.realpath(__file__))
    fabric_base_dir = os.path.join(script_dir, 'fabric/sample_cert_dir/puphpet')
    create_test_cert(-3, os.path.join(fabric_base_dir,
                                    'web/assets/js/expired_3_days.pem'))
    create_test_cert(6, os.path.join(fabric_base_dir,
                                    'tests/Puphpet/Tests/Controller/expire_6_days.pem'))
    create_test_cert(21, os.path.join(fabric_base_dir,
                                    'src/Puphpet/Controller/expire_21_days.pem'))
    create_test_cert(41, os.path.join(fabric_base_dir,
                                    'src/Puphpet/Controller/expire_41_days.pem'))
    create_test_cert(41, os.path.join(fabric_base_dir,
                                    'src/Puphpet/Domain/File/expire_41_days.der',
                                    ), is_der=True,)

    #Include the script in PYTHONPATH
    sys.path.append(os.path.realpath(os.getcwd() + '/../bin/'))

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
