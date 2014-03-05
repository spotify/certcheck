## Configuration

Actions taken by the script are determined by its command line and the
configuration file. The command line has a build-in help system:


usage: certcheck.py [-h] [--version] -c CONFIG_FILE [-v] [-s] [-d]

Simple certificate expiration check

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Location of the configuration file
  -v, --verbose         Provide extra logging messages.
  -s, --std-err         Log to stderr instead of syslog
  -d, --dont-send       Do not send data to Riemann [use for debugging]

Author: pawel.rozlach a t gmail.com

The configuration file is a plain YAML document. It's syntax is as follows:

---
lockfile: /tmp/certcheck.lock
warn_treshold: 30
critical_treshold: 15
riemann_hosts:
  static:
    - 192.168.122.16:5555:udp
    - 192.168.122.16:5555:tcp
  by_srv:
    - _riemann._tcp
    - _riemann._udp
riemann_tags:
  - production
  - class::certcheck
repo_host: git.example.net
repo_port: 22
repo_url: /example-repo
repo_masterbranch: refs/heads/production
repo_localdir: /tmp/certcheck-temprepo
repo_user: certcheck
repo_pubkey: ./certcheck_id_rsa
# format - dict, hash as a key, and value as a comment
# sha1sum ./certificate_to_be_ignored
ignored_certs:
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: "some VPN key"
  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb: "some unused certificate"

## Operation

The script connects to the $repo_user@$repo_host:$repo_port via SSH and clones
repository $repo_url to a *bare* repository in "$repo_tmpdir/repository". If
the repository already exists, it is only updated with newest referances. Only
$repo_masterbranch branch is pulled in along with all the objects it points to,
topic branches are not downloaded.

The connection is established using the $repo_pubkey pubkey, and the $repo_user
itself should have very limited privileges.

Next, the repository is scanned in search of files ending with one of the
certcheck.py:CERTIFICATE_EXTENSIONS extensions. Currently all possible
certificate extensions are listed but only ['pem', 'crt', 'cer'] are currently
supported (see certcheck.py:get_cert_expiration method). For the remaing ones
only a warning is issued.

For each certificate found a sha1sum is computed, and if the result is found in
$ignored_certs hash, then the certificate is ignored even if it expires/exp-
ired.

If the number of days till the certificate expires is less than $critical_tresh
(by default 15) - a "critical" partial status is generated, if it less than
$warn_tresh but more than $critical_tresh - a "warning" partial status is gene-
rated. Unsuported certificate yields an 'unknown' state and expired ones of
course the 'critical'.

All the 'partial status' updates are agregated and each message can only ele-
vate up the final status of the metric send to Riemann. Currently, the hierar-
chy is as follows:

       (lowest)ok->warn->critical->unknown(highest)

script errors, exceptions and unexcpected conditions result in imidiate elevation
to 'unknown' status and sending the metric to Riemann ASAP if only possible.

IP addresses/ports of the Riemann instances can be defined in two ways:
 * statically, by providing a list of riemann instances in $riemann_servers
   var. The format of the list entry is hostname:port:proto. 'proto' can be one
   of 'udp' or 'tcp'.
 * by providing a SRV record, i.e. '_riemann._udp'. All the values
   (host, port) will be resolved automatically. Protocol is chosen basing on
   the SRV entry itself.

The final metric is send to *all* Riemann instances with TTL equal to
certcheck.py:DATA_TTL == 25 hours.


=== Maintenance

In order to not to let the "$repo_tmpdir/repository" repository grow endlessly
a 'git gc' command should be executed once a day by i.e. a cronjob. It should
repack all the packs and remove dangling objects.
