#!/usr/bin/python -tt

#Make it a bit more like python3:
from __future__ import absolute_import
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

#Global imports:
from datetime import datetime, timedelta
import mock
import os
import time
import unittest

#Local import
import certcheck
import modules.file_paths as paths


class TestCertCheck(unittest.TestCase):
    @mock.patch('logging.error')
    @mock.patch('sys.exit')
    def test_config_file_parsing(self, SysExitMock, LoggingErrorMock):
        #Test malformed file loading
        certcheck.ScriptConfiguration.load_config(paths.TEST_MALFORMED_CONFIG_FILE)
        self.assertTrue(LoggingErrorMock.called)
        SysExitMock.assert_called_once_with(1)
        SysExitMock.reset_mock()

        #Test non-existent file loading
        certcheck.ScriptConfiguration.load_config(paths.TEST_NONEXISTANT_CONFIG_FILE)
        self.assertTrue(LoggingErrorMock.called)
        SysExitMock.assert_called_once_with(1)

        #Load the config file
        certcheck.ScriptConfiguration.load_config(paths.TEST_CONFIG_FILE)

        #String:
        self.assertEqual(certcheck.ScriptConfiguration.get_val("scan_dir"),
                         "./certs/")
        #List of strings
        self.assertEqual(certcheck.ScriptConfiguration.get_val("riemann_tags"),
                         ['abc', 'def'])
        #Integer:
        self.assertEqual(certcheck.ScriptConfiguration.get_val("warn_treshold"), 30)

        #Key not in config file:
        self.assertEqual(certcheck.ScriptConfiguration.get_val("not_a_field"), None)

    def test_certificate_searching(self, *unused):
        certs = certcheck.find_cert(paths.CERTIFICATES_DIR)
        self.assertEqual(set(certs), paths.ALL_CERTS_SET)

        with self.assertRaises(certcheck.RecoverableException):
            #generator needs to be evaluated
            list(certcheck.find_cert(paths.NONEXISTANT_CERTIFICATES_DIR))

    @mock.patch.object(certcheck.ScriptStatus, 'notify_immediate')  # same as below
    @mock.patch('logging.warn')  # Unused, but masks error messages
    @mock.patch.object(certcheck.ScriptStatus, 'update')
    def test_cert_expiration_parsing(self, UpdateMock, *unused):
        # -3 days is in fact -4 days, 23:59:58.817181
        # so we compensate and round up
        # additionally, openssl uses utc dates
        now = datetime.utcnow() - timedelta(days=1)

        #Test an expired certificate:
        expiry_time = certcheck.get_cert_expiration(paths.EXPIRED_3_DAYS) - now
        self.assertEqual(expiry_time.days, -3)

        #Test a good certificate:
        expiry_time = certcheck.get_cert_expiration(paths.EXPIRE_21_DAYS) - now
        self.assertEqual(expiry_time.days, 21)
        #import ipdb; ipdb.set_trace() # BREAKPOINT

        #Test a DER certificate:
        certcheck.get_cert_expiration(paths.EXPIRE_41_DAYS_DER)
        self.assertTrue(UpdateMock.called)
        self.assertEqual(UpdateMock.call_args_list[0][0][0], 'unknown')

        #Test a broken certificate:
        certcheck.get_cert_expiration(paths.BROKEN_CERT)
        self.assertTrue(UpdateMock.called)
        self.assertEqual(UpdateMock.call_args_list[0][0][0], 'unknown')

    @mock.patch('logging.warn')
    def test_file_locking(self, LoggingWarnMock, *unused):
        certcheck.ScriptLock.init(paths.TEST_LOCKFILE)

        with self.assertRaises(certcheck.RecoverableException):
            certcheck.ScriptLock.release()

        certcheck.ScriptLock.aqquire()

        certcheck.ScriptLock.aqquire()
        self.assertTrue(LoggingWarnMock.called)

        self.assertTrue(os.path.exists(paths.TEST_LOCKFILE))
        self.assertTrue(os.path.isfile(paths.TEST_LOCKFILE))
        self.assertFalse(os.path.islink(paths.TEST_LOCKFILE))

        with open(paths.TEST_LOCKFILE, 'r') as fh:
            pid_str = fh.read()
            self.assertGreater(len(pid_str), 0)
            pid = int(pid_str)
            self.assertEqual(pid, os.getpid())

        certcheck.ScriptLock.release()

        child = os.fork()
        if not child:
            #we are in the child process:
            certcheck.ScriptLock.aqquire()
            time.sleep(10)
            #script should not do any cleanup - it is part of the tests :)
        else:
            #parent
            timer = 0
            while timer < 3:
                if os.path.isfile(paths.TEST_LOCKFILE):
                    break
                else:
                    timer += 0.1
                    time.sleep(0.1)
            else:
                # Child did not create pidfile in 3 s,
                # we should clean up and bork:
                os.kill(child, 9)
                assert False

            with self.assertRaises(certcheck.RecoverableException):
                certcheck.ScriptLock.aqquire()

            os.kill(child, 11)

            #now it should succed
            certcheck.ScriptLock.aqquire()

    @mock.patch('logging.info')
    @mock.patch('logging.error')
    @mock.patch('certcheck.Riemann')
    def test_script_status(self, RiemannMock, LoggingErrorMock, LoggingInfoMock):
        #There should be at least one tag defined:
        certcheck.ScriptStatus.initialize([], [])
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        #There should be at least one Riemann host defined:
        certcheck.ScriptStatus.initialize([], ['tag1', 'tag2'])
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        #Riemann hosts should be in ip/hostname:port format:
        certcheck.ScriptStatus.initialize(['notahostname'], ['tag1', 'tag2'])
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        certcheck.ScriptStatus.initialize(['notahostname:not_an_integer'],
                                          ['tag1', 'tag2'])
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        #Riemann exceptions should be properly handled/reported:
        def side_effect(host, port):
            raise Exception("Raising exception for {0}:{1} pair")

        RiemannMock.side_effect = side_effect

        certcheck.ScriptStatus.initialize(['hostname:1234'],
                                          ['tag1', 'tag2'])
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        RiemannMock.side_effect = None
        RiemannMock.reset_mock()

        #Mock should only allow legitimate exit_statuses
        certcheck.ScriptStatus.notify_immediate("not a real status", "message")
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        certcheck.ScriptStatus.update("not a real status", "message")
        self.assertTrue(LoggingErrorMock.called)
        LoggingErrorMock.reset_mock()

        #Done with syntax checking, now initialize the class properly:
        certcheck.ScriptStatus.initialize(['hostname1:123', 'hostname2:567'],
                                          ['tag1', 'tag2'])

        proper_calls = [mock.call('hostname1', 123),
                        mock.call('hostname2', 567)]
        RiemannMock.assert_has_calls(proper_calls)
        RiemannMock.reset_mock()

        #Check if notify_immediate works
        certcheck.ScriptStatus.notify_immediate("warn", "a warning message")
        self.assertTrue(LoggingInfoMock.called)
        LoggingErrorMock.reset_mock()

        proper_call = mock.call().submit({'description': 'a warning message',
                                          'service': 'certcheck',
                                          'tags': ['tag1', 'tag2'],
                                          'state': 'warn',
                                          'host': 'mop',
                                          'ttl': 90000}
                                          )
        #This call should be issued to *both* connection mocks:
        self.assertEqual(RiemannMock.mock_calls,[proper_call, proper_call])
        RiemannMock.reset_mock()

        #update method shoul escalate only up:
        certcheck.ScriptStatus.update('warn', "this is a warning message.")
        certcheck.ScriptStatus.update('ok', '')
        certcheck.ScriptStatus.update('unknown', "this is a not-rated message.")
        certcheck.ScriptStatus.update('ok', "this is an informational message.")

        proper_call = mock.call().submit({'description':
                                            'this is a warning message. ' +
                                            'this is a not-rated message. ' +
                                            'this is an informational message.',
                                          'service': 'certcheck',
                                          'tags': ['tag1', 'tag2'],
                                          'state': 'unknown',
                                          'host': 'mop',
                                          'ttl': 90000}
                                          )
        #This call should be issued to *both* connection mocks:
        certcheck.ScriptStatus.notify_agregated()
        self.assertEqual(RiemannMock.mock_calls,[proper_call, proper_call])
        RiemannMock.reset_mock()


if __name__ == '__main__':
    unittest.main()
