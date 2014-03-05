# _Certchecker_

_Certchecker is a certificate expiration check capable of scanning GIT repos
and sending data on expiring/expired certificates back to the monitoring system
(currently only Riemann)._

## Project Setup

In order to run certchecker you need to following dependencies installed:
- Bernhard - Riemann client library (https://github.com/banjiewen/bernhard)
- Google's protobuf library
- yaml bindings for python (http://pyyaml.org/)
- Dulwich - python implementation of GIT (https://www.samba.org/~jelmer/dulwich/docs/)
- ssh command in your PATH
- argparse library

You can also use debian packaging rules from debian/ directory to build a deb
package.

## Testing

Currenlty the unittest python library is used to perform all the testing. In
test/ directory you can find:
- modules/ - modules used by unittests
- moduletests/ - the unittests themselves
- fabric/ - sample input files and test certificates temporary directories
- output_coverage_html/ - coverage tests results in a form of an html webpage
- test.py - script to start all the unittests

All the dependencies required for performing the unittests are decribed in debian
packaging scripts and are as follows:
- unittests2
- coverage
- python-mock
- openssl command in the PATH

Plus all the dependencies mentioned in 'Project Setup' section.

## Usage

Please see the doc/USAGE.md file for details.

## Contributing

All patches are welcome ! Please use Github issue tracking and/or create a pull
request.

## License

FIXME - Put the licence here
