#!/usr/bin/env python

#Make it a bit more like python3:
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

#Imports:
#from os import listdir
#from os.path import isfile, join

from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import load_certificate
from datetime import datetime
from eagleeye.riemann import Riemann
import argparse
import fcntl
import json
import logging
import logging.handlers
import os
import socket
import sys
import traceback

#Constants:
LOCKFILE_LOCATION = './'+os.path.basename(__file__)+'.lock'
CONFIGFILE_LOCATION = './'+os.path.basename(__file__)+'.conf'
DATA_TTL = 25*60*60  # Data gathered by the script run is valid for 25 hours.
SERVICE_NAME = 'certcheck'
CERTIFICATE_EXTENSIONS = ['der', 'crt', 'pem', 'cer', 'p12', 'pfx', ]


class RecoverableException(Exception):
    """
    Exception used to differentiate between errors which should be reported
    to Riemann, and the ones that should be only logged due to their severity
    """
    pass


class ScriptConfiguration(object):

    _config = dict()

    @classmethod
    def load_config(cls, file_path):
        """
        @param string file_path     path to the configuration file
        """
        try:
            with open(file_path, 'r') as fh:
                cls._config = json.load(fh)
        except IOError as e:
            logging.error("Failed to open config file {0}: {1}".format(
                file_path, e))
            sys.exit(1)
        except ValueError as e:
            logging.error("File {0} is not a proper json document: {1}".format(
                file_path, e))
            sys.exit(1)

    @classmethod
    def get_val(cls, key):
        return cls._config.get(key, None)


class ScriptStatus(object):

    _STATES = {'ok': 0,
               'warn': 1,
               'critical': 2,
               'unknown': 3,
               }

    _exit_status = None
    _exit_message = ''
    _riemann_connections = []
    _riemann_tags = None
    _hostname = ''

    @classmethod
    def initialize(cls, riemann_hosts, riemann_tags):
        cls._riemann_tags = riemann_tags
        cls._hostname = socket.gethostname()

        if not riemann_tags:
            logging.error('There should be at least one riemann tag defined.')
            return
        for riemann_host in riemann_hosts:
            try:
                host, port = riemann_host.split(':')
                port = int(port)
            except ValueError:
                logging.error("{0} is not a correct Riemann hostname.".format(
                    riemann_host) + " Please try hostname:port or ipaddress:port")
                continue

            try:
                riemann_connection = Riemann(host, port)
            except Exception as e:
                logging.error("Failed to connect to Rieman host {0}: {1}, ".format(
                    riemann_host, str(e)) + "address has been exluded from the list.")
                logging.error("traceback: {0}".format(traceback.format_exc()))
                continue

            logging.debug("Connected to Riemann instance {0}".format(riemann_host))
            cls._riemann_connections.append(riemann_connection)

        if not cls._riemann_connections:
            logging.error("there are no active connections to Riemann, " +
                          "metrics will not be send!")

    @classmethod
    def notify_immediate(cls, exit_status, exit_message):
        """
        Imediatelly send given data to Riemann
        """
        logging.info("notify_immediate, " +
                     "exit_status=<{0}>, exit_message=<{1}>".format(
                     exit_status, exit_message))
        event = {
            'host': cls._hostname,
            'service': SERVICE_NAME,
            'state': exit_status,
            'description': exit_message,
            'tags': cls._riemann_tags,
            'ttl': DATA_TTL,
        }
        for riemann_connection in cls._riemann_connections:
            riemann_connection.submit(event)

    @classmethod
    def notify_agregated(cls):
        """
        Send all agregated data to Riemann
        """
        logging.info("notify_agregated, exit_status=<{0}>, exit_message=<{1}>".format(
            cls._exit_status, cls._exit_message))
        event = {
            'host': cls._hostname,
            'service': SERVICE_NAME,
            'state': cls._exit_status,
            'description': cls._exit_message,
            'tags': cls._riemann_tags,
            'ttl': DATA_TTL,
        }
        for riemann_connection in cls._riemann_connections:
            riemann_connection.submit(event)

    @classmethod
    def update(cls, exit_status, exit_message):
        """
        Accumullate a small bit of data in class fields
        """
        logging.debug("updating script status, exit_status=<{0}>, exit_message=<{1}>".format(
            exit_status, exit_message))
        if exit_status not in cls._STATES:
            logging.error("{0} is not a valid state, aborting!".format(exit_status))
        if cls._exit_status is None:
            cls._exit_status = exit_status
        if cls._STATES[cls._exit_status] < cls._STATES[exit_status]:
            cls._exit_status = exit_status
        # ^ we only escalate up...
        if exit_message:
            if cls._exit_message:
                cls._exit_message += ' '
            cls._exit_message += exit_message


class ScriptLock(object):
    #python lockfile is brain-damaged, we have to write our own class :/
    _fh = None
    _file_path = None

    @classmethod
    def init(cls, file_path):
        cls._file_path = file_path

    @classmethod
    def aqquire(cls):
        if cls._fh:
            logging.warn("File lock already aquired")
            return
        try:
            cls._fh = open(cls._file_path, 'w')
            #flock is nice because it is automatically released when the
            #process dies/terminates
            fcntl.flock(cls._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            if cls._fh:
                cls._fh.close()
            raise RecoverableException("{0} ".format(cls._file_path) +
                                       "is already locked by a different " +
                                       "process or cannot be created.")
        cls._fh.write(str(os.getpid()))
        cls._fh.flush()

    @classmethod
    def release(cls):
        if not cls._fh:
            raise RecoverableException("Trying to release non-existant lock")
        cls._fh.close()
        cls._fh = None
        os.unlink(cls._file_path)


def parse_command_line():
    parser = argparse.ArgumentParser(
        description='Simple certificate expiration check',
        epilog="Author: prozlach@spotify.com",
        add_help=True,)
    parser.add_argument(
        '--version',
        action='version',
        version='1.0')
    parser.add_argument(
        "-c", "--config-file",
        action='store',
        required=True,
        help="Location of the configuration file")
    parser.add_argument(
        "-v", "--verbose",
        action='store_true',
        required=False,
        help="Provide extra logging messages.")
    parser.add_argument(
        "-s", "--std-err",
        action='store_true',
        required=False,
        help="Log to stderr instead of syslog")

    return parser.parse_args()


def find_cert(path):
    if not os.path.isdir(path):
        raise RecoverableException("Directory {0} does not exist".format(path))
    logging.debug("Scanning directory {0}".format(path))
    for root, sub_folders, files in os.walk(path):
        for file in files:
            if len(file) >= 5 and file[-4] == '.' and \
                    file[-3:] in CERTIFICATE_EXTENSIONS:
                yield os.path.join(root, file)


def get_cert_expiration(path):
    if path[-3:] in ['pem', 'crt', 'cer']:
        try:
            #Many bad things can happen here, but still - we can recover! :)
            with open(path, 'r') as fh:
                cert_data = load_certificate(FILETYPE_PEM, fh.read())
                expiry_date = cert_data.get_notAfter()
                #Return datetime object:
                return datetime.strptime(expiry_date, '%Y%m%d%H%M%SZ')
        except Exception as e:
            msg = "Script cannot parse certificate {0}: {1}".format(path, str(e))
            logging.warning(msg)
            ScriptStatus.notify_immediate('unknown', msg)
    else:
        ScriptStatus.update('unknown',
                            "Certificate {0} is of unsupported type, ".format(path) +
                            "the script cannot check the expiry date.")

    return None


def main():
    try:
        args = parse_command_line()

        #Configure logging:
        logger = logging.getLogger()
        if args.verbose:
            logger.setLevel(logging.DEBUG)
        if args.std_err:
            handler = logging.StreamHandler()
        else:
            handler = logging.handlers.SysLogHandler(address='/dev/log')
        logger.addHandler(handler)

        logger.debug("Command line arguments: {0}".format(args))

        #FIXME - Remamber to correctly configure syslog, otherwise rsyslog will
        #discard messages
        ScriptConfiguration.load_config(args.config_file)

        ScriptStatus.initialize(
            riemann_hosts=ScriptConfiguration.get_val("riemann_hosts"),
            riemann_tags=ScriptConfiguration.get_val("riemann_tags"),
        )

        # verify the configuration
        msg = []
        if ScriptConfiguration.get_val('warn_treshold') <= 0:
            msg.append('Certificate expiration warn threshold should be > 0.')
        if ScriptConfiguration.get_val('critical_treshold') <= 0:
            msg.append('Certificate expiration critical threshold should be > 0.')
        if ScriptConfiguration.get_val('critical_treshold') >= ScriptConfiguration.get_val(
                'warn_treshold'):
            msg.append('Warninig threshold should be greater than critical treshold.')

        #if there are problems with thresholds then there is no point in continuing:
        ScriptStatus.notify_immediate('unknown', "Configuration file contains errors" +
                                      msg)

        ScriptLock.init(args.lock_file)
        ScriptLock.aqquire()

        for certfile in find_cert(ScriptConfiguration.get_val("scan_dir")):
            cert_expiration = get_cert_expiration(certfile)
            if cert_expiration is None:
                continue
            now = datetime.now()
            time_left = cert_expiration - now  # timedelta object
            if time_left.days < 0:
                ScriptStatus.update('critical',
                                    "Certificate {0} expired {1} days ago.".format(
                                    certfile, abs(time_left.days)))
            elif time_left.days == 0:
                ScriptStatus.update('critical',
                                    "Certificate {0} expires today.".format(certfile))
            elif time_left.days < ScriptConfiguration.get_val("crit_treshold"):
                ScriptStatus.update('critical',
                                    "Certificate {0} is about to expire in {1} days.".format(
                                    certfile, time_left.days))
            elif time_left.days < ScriptConfiguration.get_val("warn_treshold"):
                ScriptStatus.update('warn',
                                    "Certificate {0} is about to expire in {1} days.".format(
                                    certfile, time_left.days))
            else:
                logger.info("{0} expires in {1} days - OK!".format(
                    certfile, time_left.days))

        ScriptStatus.notify_agregated()
        ScriptLock.release()
        sys.exit(0)

    except RecoverableException as e:
        msg = str(e)
        logging.critical(msg)
        ScriptStatus.notify_immediate('unknown', msg)
        sys.exit(1)
    except Exception as e:
        msg = "Exception occured: {0}".format(e.__class__.__name__)
        logging.critical(msg)
        extra = "Traceback: {0}".format(traceback.format_exc())
        logging.critical(extra)
        sys.exit(1)

if __name__ == '__main__':
    main()
