#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import requests
import sys
import time
from datetime import datetime, timedelta
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper


def create_alert():
    description = x['summary'] + "\n\n" + " Full report: <CVE-SEARCH URL>/cve/" + x['id']
    artifacts = [
      AlertArtifact(dataType='cve', data=x['id']),
      AlertArtifact(dataType='fqdn', data=hostnames),
    ]

    # Prepare the Alert
    sourceRef = str(uuid.uuid4())[0:6]
    alert = Alert(title='New Alert',
           tlp=3,
           tags=['vuln_info', 'cvss_score: ' + str(cvss) + '/10.0', 'found: ' + str(hits)],
           description=description,
           severity=sev,
           caseTemplate='New Vulnerability',
           type='cve-search',
           source='cve_to_thehive',
           sourceRef=sourceRef,
           artifacts=artifacts)

    # Create the Alert
    id = None
    response = api.create_alert(alert)
    if response.status_code == 201:
          id = response.json()['id']
    else:
          print('ko: {}/{}'.format(response.status_code, response.text))
          sys.exit(0)

# Collect CVE data
yesterday = datetime.now() + timedelta(days=-1)

api = TheHiveApi('<THEHIVE URL>', '<THE HIVE API KEY>')
cvs_url = '<CVE SEARCH URL>/api/last?limit=200'
# Limit to 100, if there is more, it's most likely a Windows patch...
r7_url = '<RAPID7 PORTAL>/api/3/assets/search?size=100'

r = requests.get(cvs_url)
data = r.json()

for x in data:
    if yesterday.strftime('%Y-%m-%d') in x['Modified']:
        cvss = x.get('cvss')
        if cvss:
         score=int(cvss)
         # Only care about more severe issues .. at least for now
         if score >= 8:
         # But prepare to handle all sorts..
          if score >= 8:
               sev=4
          elif score <8 and score >= 4:
               sev=3
          elif score < 4:
               sev=2

          # Check CVE with R7 / If you are using Tenable, just replace or if you are using both, check them all =)
          data = '{ "match": "all", "filters": [ { "field": "cve", "operator": "is", "value": "' +  x['id'] + '" } ]}'
          headers = {'Content-type': 'application/json', 'Authorization': 'Basic <R7 API KEY>'}
          r7 = requests.post(r7_url, data=data, headers=headers)
          vuln_data = r7.json()

          # Get hostnames
          hostnames = []
          for key in vuln_data['resources']:
              hostnames.append(key['hostName'])

          time.sleep(3)
          try:
            if vuln_data['page']['totalResources'] > 0:
                   hits = vuln_data['page']['totalResources']
            else:
                   hits = 0
          except:
              hits = 0
          # Sleep some
          time.sleep(3)

          if hits >0:
              create_alert()
          elif hits == 0 and sev >= 4:
              create_alert()
