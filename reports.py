#!/usr/bin/env python
from __future__ import print_function
import glob
import os.path
import json
import md5

def get_hostinfo(data):
  """ Parse out host data from reports """
  ips = data.get('IPv4Addrs', [])
  ips = ips if ips else []

  return {
    'name': data.get('ServerName'),
    'os': '%s:%s' % (data['Family'], data['Release']),
    'ipv4': ','.join(ips),
    'container': data.get('Container', {}).get('Image')
  }

def get_cves(data, family='nvd'):
  """ Get the CVEs and pair down to data we care about """
  cves = []
  cves_results = data.get('ScannedCves', {})
  cves_results = cves_results if cves_results is not None else {}

  for cve, cve_data in cves_results.items():
      if cve_data['CveContents'] is None:
        continue

      confidence = cve_data.get('Confidence', {}).get('Score', {})
      nvd = cve_data['CveContents'].get(family)
      nvd = cve_data['CveContents'].get('nvd', {}) if nvd is None else nvd
      score = nvd.get('Cvss2Score')

      if score == 0:
        continue

      cves.append({
        'cve': cve,
        'score': score,
        'summary': nvd.get('Summary'),
        'confidence': confidence,
        'references': [r['Link'] for r in nvd.get('References', [])]
      })
  return cves

def get_all_results(target):
  report_dir = os.path.abspath('./data/results/%s/' % target)
  return glob.glob(report_dir + '/**/*.json')


def get_current_results(target):
  report_dir = os.path.abspath('./data/results/%s/current/' % target)

  if os.path.exists(report_dir):
    report_dir = os.readlink(report_dir)
    return glob.glob(report_dir + '/*.json')

  return []

def main():
  target = 'ready2hire.org'.replace('.', '-')
  reports = get_all_results(target)
  print("Found %s reports" % len(reports))
  aggregate = {}
  errors = []
  for report in reports:
    with open(report, 'r') as fh:
      contents = fh.read()

      hashed = md5.new(contents).hexdigest()
      data = json.loads(contents)
      host = get_hostinfo(data)
      family = data['Family']

      errors.append(data.get('Errors'))

      for c in get_cves(data, family):
        if c['cve'] not in aggregate:
          aggregate[c['cve']] = c
          aggregate[c['cve']]['hosts'] = []
        aggregate[c['cve']]['hosts'].append(host)
      

  cves = aggregate.values()
  cves = sorted(cves, key=lambda c: (c['score'], c['cve']))

  print(json.dumps({'cves':cves, 'errors': errors}, indent=4, sort_keys=False))

main()
