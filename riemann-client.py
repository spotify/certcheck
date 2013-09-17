#!/usr/bin/env python

import bernhard

import subprocess as sp
import socket
import os
import sys
import json
import dns.resolver

CONFIG_PATH = '/etc/spotify/riemann_client.json'

transports = {
    'tcp': bernhard.TCPTransport,
    'udp': bernhard.UDPTransport
}


def load_configuration():
    with open(CONFIG_PATH) as f:
        C = json.load(f)

    C['protocols'] = filter(lambda p: p.lower(), C.get('protocols', []))

    if 'dns_base' not in C:
        raise Exception("Expected configuration: dns_base")

    if not C['protocols']:
        raise Exception("Expected configuration value for: protocols")

    return C


def get_targets(C):
    protocol_targets = {}

    for protocol in C['protocols']:
        srv_key = C['dns_base'] + '._' + protocol

        try:
            resolved = dns.resolver.query(srv_key, 'SRV')
        except dns.resolver.NXDOMAIN:
            continue

        for rdata in resolved:
            result = (
                str(dns.resolver.query(str(rdata.target), 'A')[0]),
                rdata.port
            )
            protocol_targets.setdefault(protocol, []).append(result)

    if not protocol_targets:
        raise Exception("No targets found")

    return protocol_targets


def get_tag_for_service(C, service, tags):
    if 'service_map' not in C:
        return list(tags)

    service_map = C['service_map']

    if service not in service_map:
        return list(tags)

    return tags + service_map[service]


def run_script_and_send_status(C, script, severity, protocol_targets, ttl):
    message, err = sp.Popen([script], stdout=sp.PIPE).communicate()

    message = message.rstrip()

    if message == "0":
        message = None
        state = 'ok'
    else:
        state = 'critical'

    tags = get_tag_for_service(C, os.path.basename(script), C['tags'])

    attributes = dict(C.get('attributes', {}))
    attributes["severity"] = severity

    tags.append("monitoring-hooks")

    event = {
        'host': socket.gethostname(),
        'service': os.path.basename(script),
        'state': state,
        'tags':  tags,
        'attibutes': attributes
    }

    if ttl is not None:
        event['ttl'] = ttl

    if message is not None:
        event['description'] = message

    for proto in C['protocols']:
        targets = protocol_targets.get(proto)

        if not targets:
            continue

        transport = transports.get(proto)

        if not transport:
            raise Exception("No transport for: " + proto)

        for (target, port) in targets:
            print "Sending Event:", proto, target, port, event
            c = bernhard.Client(host=target, port=port, transport=transport)

            try:
                c.send(event)
            except Exception, e:
                print "Failed to send", str(e)
                continue


def main(args):
    if len(args) >= 1:
        ttl = int(args[0])
    else:
        ttl = None

    try:
        C = load_configuration()
    except Exception, e:
        print 'riemann_client: could not load configuration: ' + str(e)
        return 1

    protocol_targets = get_targets(C)

    for severity in C['severities']:
        directory = os.path.join(C['scripts_directory'], severity)

        if not os.path.isdir(directory):
            continue

        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            try:
                run_script_and_send_status(C, path, severity, protocol_targets, ttl)
            except Exception, e:
                print "Failed to run %s with %s" % (path, str(e))

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
