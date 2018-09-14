#!/usr/bin/env python
from __future__ import print_function
import os
import sqlite3
import subprocess
from datetime import datetime

# @todo try catch updates

def update_oval(data_path):
  state = get_oval_state(data_path)
  gocve = os.path.abspath('./bin/goval-dictionary')
  distros = [
    ('alpine', ['3.3', '3.4', '3.5', '3.6']),
    ('debian', [7, 8, 9, 10]),
    ('redhat', [5, 6, 7]),
    ('ubuntu', [12, 14, 16, 18]),
    ('amazon', [])
  ]

  for [distro, versions] in distros:
    # @todo execute with docker
    versions = [str(v) for v in versions]
    command = [
      gocve, 'fetch-%s' % distro,
        '-log-dir=%s/log/' % data_path,
        '-dbtype=sqlite3',
        '-dbpath=%s/oval.sqlite3' % data_path,
        
    ] + versions
    process = subprocess.Popen(command)
    process.wait()

def update_cve(data_path):
 state = get_cve_state(data_path)
  goval = os.path.abspath('./bin/go-cve-dictionary')
  now = datetime.now()
  for year in range(2012, now.year + 1):
    # @todo execute with docker
    process = subprocess.Popen([
      goval, 'fetchnvd',
        '-log-dir=%s/log/' % data_path,
        '-dbtype=sqlite3',
        '-dbpath=%s/cve.sqlite3' % data_path,
        '-years',  str(year),
      ])
    process.wait()


def get_oval_state(data_path):
  conn = sqlite3.connect('%s/oval.sqlite3' % data_path)
  cursor = conn.cursor()
  [count, updated_at] = cursor.execute('SELECT Count(*),  Max(updated) as "[timestamp]" FROM advisories').fetchone()
  families = [f for f in cursor.execute('SELECT distinct family, COUNT(os_version) FROM roots GROUP BY family').fetchall()]
  return {
    'count': count,
    'families': families,
    'updated_at': updated_at
  }

def get_cve_state(data_path):
  conn = sqlite3.connect('%s/cve.sqlite3' % data_path)
  cursor = conn.cursor()
  [count, updated_at] = cursor.execute('SELECT Count(*), Max(updated_at) as "[timestamp]" FROM nvds').fetchone()
  conn.close()
  return {
    'count': count,
    'updated_at': updated_at
  }


def main():
  data_path = os.path.abspath('./data')
  gocve = os.path.abspath('./bin/goval-dictionary')

  if not os.path.exists(gocve):
    print("[!] You need to install goval-dictionary & go-cve-dictionary")
    exit(1)

  update_cve(data_path)
  update_oval(data_path)

  with open(data_path + '/.last_update', 'w') as fh:
    fh.write(str(datetime.now()))

main()



