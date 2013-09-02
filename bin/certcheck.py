#!/usr/bin/env python

#Make it a bit more like python3:
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

#Imports:
from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import load_certificate
from datetime import datetime, timedelta
from eagleeye.riemann import Riemann
import argparse
import fcntl
import hashlib
import logging
import logging.handlers as lh
import os
import socket
import sys
import yaml

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
                cls._config = yaml.load(fh)
        except IOError as e:
            logging.error("Failed to open config file {0}: {1}".format(
                file_path, e))
            sys.exit(1)
        except (yaml.parser.ParserError, ValueError) as e:
            logging.error("File {0} is not a proper yaml document: {1}".format(
                file_path, e))
            sys.exit(1)

    @classmethod
    def get_val(cls, key):
        return cls._config[key]


class ScriptStatus(object):

    _STATES = {'ok': 0,
               'warn': 1,
               'critical': 2,
               'unknown': 3,
               }

    _exit_status = 'ok'
    _exit_message = ''
    _riemann_connections = []
    _riemann_tags = None
    _hostname = ''
    _debug = None

    @classmethod
    def _send_data(cls, event):
        for riemann_connection in cls._riemann_connections:
            logging.info('Sending event {0}, '.format(str(event)) +
                         'using riemann conn {0}:{1}'.format(
                             riemann_connection.host, riemann_connection.port)
                         )
            if not cls._debug:
                try:
                    riemann_connection.submit(event)
                except Exception as e:
                    logging.exception("Failed to send event to Rieman host: " +
                                      "{0}".format(str(e))
                                      )
                    continue
                else:
                    logging.info("Event sent succesfully")
            else:
                logging.info('Debug flag set, I am performing no-op instead of '
                             'real sent call')

    @classmethod
    def initialize(cls, riemann_hosts, riemann_port, riemann_tags, debug=False):
        cls._riemann_tags = riemann_tags
        cls._hostname = socket.gethostname()
        cls._debug = debug

        if not riemann_tags:
            logging.error('There should be at least one riemann tag defined.')
            return  # Should it sys.exit or just return ??
        for riemann_host in riemann_hosts:
            try:
                riemann_connection = Riemann(riemann_host, riemann_port)
            except Exception as e:
                logging.exception("Failed to connect to Rieman host {0}: {1}, ".format(
                    riemann_host, str(e)) + "address has been exluded from the list.")
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
        if exit_status not in cls._STATES:
            logging.error("Trying to issue an immediate notification" +
                          "with malformed exit_status: " + exit_status)
            return

        if not exit_message:
            logging.error("Trying to issue an immediate" +
                          "notification without any message")
            return

        logging.warning("notify_immediate, " +
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

        cls._send_data(event)

    @classmethod
    def notify_agregated(cls):
        """
        Send all agregated data to Riemann
        """

        if cls._exit_status == 'ok' and cls._exit_message == '':
            cls._exit_message = 'All certificates are OK'

        logging.debug("notify_agregated, exit_status=<{0}>, exit_message=<{1}>".format(
            cls._exit_status, cls._exit_message))

        event = {
            'host': cls._hostname,
            'service': SERVICE_NAME,
            'state': cls._exit_status,
            'description': cls._exit_message,
            'tags': cls._riemann_tags,
            'ttl': DATA_TTL,
        }

        cls._send_data(event)

    @classmethod
    def update(cls, exit_status, exit_message):
        """
        Accumullate a small bit of data in class fields
        """
        if exit_status not in cls._STATES:
            logging.error("Trying to do the status update" +
                          "with malformed exit_status: " + exit_status)
            return

        logging.info("updating script status, exit_status=<{0}>, exit_message=<{1}>".format(
            exit_status, exit_message))
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
    parser.add_argument(
        "-d", "--dont-send",
        action='store_true',
        required=False,
        help="Do not send data to Riemann [use for debugging]")

    args = parser.parse_args()
    return {'std_err': args.std_err,
            'verbose': args.verbose,
            'config_file': args.config_file,
            'dont_send': args.dont_send,
            }


def find_cert(path):
    if not os.path.isdir(path):
        raise RecoverableException("Directory {0} does not exist".format(path))
    logging.debug("Scanning directory {0}".format(path))
    for root, sub_folders, files in os.walk(path):
        for file in files:
            if len(file) >= 5 and file[-4] == '.' and \
                    file[-3:] in CERTIFICATE_EXTENSIONS:
                logging.debug("Certificate found: {0}".format(file))
                yield os.path.join(root, file)


def get_cert_expiration(path):
    ignored_certs = ScriptConfiguration.get_val("ignored_certs")
    if path[-3:] in ['pem', 'crt', 'cer']:
        try:
            #Many bad things can happen here, but still - we can recover! :)
            with open(path, 'r') as fh:
                cert = fh.read()
                cert_hash = hashlib.sha1(cert).hexdigest()
                if cert_hash in ignored_certs:
                    #This cert should be ignored
                    logging.notice("certificate {0} (sha1sum: {1})".format(
                                   path, cert_hash) + " has been ignored.")
                    return None
                cert_data = load_certificate(FILETYPE_PEM, cert)
                expiry_date = cert_data.get_notAfter()
                #Return datetime object:
                return datetime.strptime(expiry_date, '%Y%m%d%H%M%SZ')
        except Exception as e:
            msg = "Script cannot parse certificate {0}: {1}".format(path, str(e))
            logging.warn(msg)
            ScriptStatus.update('unknown', msg)
            return None
    else:
        ScriptStatus.update('unknown',
                            "Certificate {0} is of unsupported type, ".format(path) +
                            "the script cannot check the expiry date.")
        return None


def main(config_file, std_err=False, verbose=True, dont_send=False):
    try:
        #Configure logging:
        fmt = logging.Formatter('%(filename)s[%(process)d] %(levelname)s: %(message)s')
        logger = logging.getLogger()
        if verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        if std_err:
            handler = logging.StreamHandler()
        else:
            handler = lh.SysLogHandler(address='/dev/log',
                                       facility=lh.SysLogHandler.LOG_USER)
        handler.setFormatter(fmt)
        logger.addHandler(handler)

        logger.info("Certcheck is starting, command line arguments:" +
                    "config_file={0}, ".format(config_file) +
                    "std_err={0}, ".format(std_err) +
                    "verbose={0}, ".format(verbose)
                    )

        #FIXME - Remamber to correctly configure syslog, otherwise rsyslog will
        #discard messages
        ScriptConfiguration.load_config(config_file)

        logger.debug("Scandir is: " +
                     "{0}".format(ScriptConfiguration.get_val("scan_dir")),
                     ", warn_thresh is {0}".format(
                         ScriptConfiguration.get_val('warn_treshold')),
                     ", crit_thresh is {0}".format(
                         ScriptConfiguration.get_val('critical_treshold'))
                     )

        ScriptStatus.initialize(
            riemann_hosts=ScriptConfiguration.get_val("riemann_hosts"),
            riemann_port=ScriptConfiguration.get_val("riemann_port"),
            riemann_tags=ScriptConfiguration.get_val("riemann_tags"),
            debug=dont_send,
        )

        # verify the configuration
        msg = []
        if ScriptConfiguration.get_val('warn_treshold') <= 0:
            msg.append('certificate expiration warn threshold should be > 0.')
        if ScriptConfiguration.get_val('critical_treshold') <= 0:
            msg.append('certificate expiration critical threshold should be > 0.')
        if ScriptConfiguration.get_val('critical_treshold') >= ScriptConfiguration.get_val(
                'warn_treshold'):
            msg.append('warninig threshold should be greater than critical treshold.')

        #if there are problems with thresholds then there is no point in continuing:
        if msg:
            ScriptStatus.notify_immediate('unknown',
                                          "Configuration file contains errors: " +
                                          ','.join(msg))
            sys.exit(1)

        ScriptLock.init(ScriptConfiguration.get_val('lockfile'))
        ScriptLock.aqquire()

        for certfile in find_cert(ScriptConfiguration.get_val("scan_dir")):
            cert_expiration = get_cert_expiration(certfile)
            if cert_expiration is None:
                continue
            # -3 days is in fact -4 days, 23:59:58.817181
            # so we compensate and round up
            # additionally, openssl uses utc dates
            now = datetime.utcnow() - timedelta(days=1)
            time_left = cert_expiration - now  # timedelta object
            if time_left.days < 0:
                ScriptStatus.update('critical',
                                    "Certificate {0} expired {1} days ago.".format(
                                    certfile, abs(time_left.days)))
            elif time_left.days == 0:
                ScriptStatus.update('critical',
                                    "Certificate {0} expires today.".format(certfile))
            elif time_left.days < ScriptConfiguration.get_val("critical_treshold"):
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
    except AssertionError as e:
        #Unittest require it:
        raise
    except Exception as e:
        msg = "Exception occured: {0}".format(e.__class__.__name__)
        logging.exception(msg)
        sys.exit(1)

if __name__ == '__main__':
    args_dict = parse_command_line()

    main(**args_dict)
