#!/usr/bin/env python
from __future__ import print_function
from optparse import OptionParser
import subprocess
import re
import os
import os.path
import tempfile

def generate_config(config={}):
  """ Generate the config file for vuls to read for scans """
  content = '\n'.join([
    '[servers]',
    '',
    '[servers.%(target)s]',
    'os = "%(os)s"',
    'user = "%(user)s"',
    'host = "%(host)s"',
    'port = "%(port)s"',
    # 'keyPath = ""',
    '',
  ])

  if config.get('containers', False):
    content += '\n'.join([
      '[servers.%(target)s.containers]',
      'type = "docker"',
      'includes = ["${running}"]'
    ])


  here = os.path.abspath('./.tmp')
  conf =  content % config
  config_file = None
  with tempfile.NamedTemporaryFile(dir=here, suffix='.toml', delete=False) as fh:
    fh.write(conf)
    config_file = fh.name
  return config_file

def check_dictionaries(data_path):
  """ Ensure the dictionaries for vulns already exist """
  if not os.path.exists(data_path + '/cve.sqlite3'):
    return [False, 'Missing dictionary for CVE']

  if not os.path.exists(data_path + '/oval.sqlite3'):
    return [False, 'Missing dictionary for OVAL']

  return [True, 'Dictionaries exist for CVE & OVAL']

def check_required_options(opts, parser):
    missing = []
    for option in parser.option_list:
      if re.match(r'^\[required\]', option.help) and eval('opts.' + option.dest) == None:
          missing.extend(option._long_opts)
    
    if not missing:
      return
    
    parser.print_help()
    parser.error('Missing [required] parameters: ' + str(missing))


def scan_target(config):
  data_path = config.get('data_path')
  vuls_path = os.path.abspath('./bin/vuls')

  if not os.path.exists(vuls_path):
    return [False, 'It appears vuls has not been installed, run the ./install.sh']

  config_file = generate_config(config)

  print("Using config %s " % config_file)

  # @todo execute with docker
  process = subprocess.Popen([
      vuls_path, 'scan',  
      '-deep',
      '-config=%s' % config_file,
      '-results-dir=%s/results/%s/' % (data_path, config['target']),
      '-log-dir=%s/log/%s' % (data_path, config['target']),
      config.get('target', 'localhost')
  ])
  process.wait()

  # @todo execute with docker
  process = subprocess.Popen([
    vuls_path, 'report',
    '-config=%s' % config_file,
    '-results-dir=%s/results/%s/' % (data_path, config['target']),
    '-log-dir=%s/log/%s' % (data_path, config['target']),
    '-cvedb-type=sqlite3',
    '-cvedb-path=%s/cve.sqlite3' % data_path,
    '-ovaldb-type=sqlite3',
    '-ovaldb-path=%s/oval.sqlite3' % data_path,
    '-format-json'
  ])
  process.wait()

  os.remove(config_file)
  return [True, '']


def main():
  defaults  = {
    'target': os.environ.get('SCAN_TARGET', '127.0.0.1'),
    'use_port' :int(os.environ.get('SCAN_USE_PORT', 22)),
    'user': os.environ.get('SCAN_USER', 'root')
    'os': os.environ.get('SCAN_OS', 'redhat')
  }

  parser = OptionParser()
  parser.add_option("-t", "--target", help="[required] Target you want to scan", default= defaults['target'])
  parser.add_option("-p", "--port", help="[required] SSH port of target", default= defaults['port'])
  parser.add_option("-u", "--user", help="[required] SSH user for target", default=default['user'])
  parser.add_option("-o", "--os", help="OS of the target you want to scan", default=defaults['os'])
  parser.add_option("-c", "--containers", help="Include containers in the scan", default=False)
  parser.add_option("-d", "--data", help="Data directory", default=os.path.abspath('./data/'))
  options, _args = parser.parse_args()
  check_required_options(options, parser)

  print("Runnning as %s" % os.getuid())
  data_path = os.path.abspath(options.data)

  if not os.path.exists(data_path):
    print("That data path does not exist")
    exit(1)

  [ready, message] = check_dictionaries(data_path)

  if not ready:
    print(message)
    exit(2)

  config = {
    'host': options.target,
    'port': options.port,
    'user': options.user,
    'os': options.os,
    'containers': options.containers
    'data_path': data_path,
  }


  
  if config['host']  in ['localhost', '127.0.0.1']:
    config['port'] = 'local'
    config['host'] = 'localhost'

  config['target'] = config['host'].replace('.', '-')


  scan_target(config)


main()