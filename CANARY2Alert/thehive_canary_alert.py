#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import requests
import sys
import json
import time
from datetime import datetime, timedelta
import uuid
from datetime import date
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper


def create_alert(canary):
    # Hmm.. looks crazy, should of course re-write ..
    description =  "Incident date: " + str(canary[0]) + "\n\n" + "Attack Type: " + str(canary[1]) + "\n\n" + "Targeted Canary IP: " + str(canary[2]) + "\n\n" + "Flock: " + str(canary[3]) + "\n\n" + "Targeted Canary hostname: " + str(canary[4])  + "\n\n" + "Attacker IP: " + str(canary[5])  + "\n\n" + "Attacker Hostname: " + str(canary[6])  + "\n\n" + "Attacker Src Port: " + str(canary[7])
    
    artifacts = [
      AlertArtifact(dataType='ip', data=str(canary[5])),
    ]

    # Prepare the Alert
    sourceRef = str(uuid.uuid4())[0:6]
    alert = Alert(title='New Alert',
           tlp=3,
           tags=['canary_alert', 'attack_type=' + str(canary[1])],
           description=description,
           severity=4,
           caseTemplate='New Canary alert',
           type='canary-alert',
           source='canary_to_thehive',
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

# Prepare stuff
api = TheHiveApi('TheHive-URL', 'API-KEY')
# Get latest ID, using ID enables us to check more often and we don't have to care about time diff between checks
# Waldo file
with open('canary_id.txt','r') as f:
     value = sum(map(int, f))
f.close()

# Canary URL
url = 'https://<XXXXX>/api/v1/incidents/all'
payload = {
        'auth_token': 'CANARY API TOKEN',
        'limit':'1',
        'incidents_since':value
        }

r = requests.get(url, params=payload)
result = r.json()

canary = []
try:
    for a in result['incidents']:
        canary.append(a['description'].get('created_std'))
        canary.append(a['description'].get('description'))
        canary.append(a['description'].get('dst_host'))
        canary.append(a['description'].get('flock_name'))
        canary.append(a['description'].get('name'))
        canary.append(a['description'].get('src_host'))
        canary.append(a['description'].get('src_host_reverse'))
        canary.append(a['description'].get('src_port'))
        canary.append(a['hash_id'])

    # Update the ID waldo file
    if result['max_updated_id']:
       value+= 1
       with open('canary_id.txt','w') as f:
            f.write(str(value))
except:
    print('No new alerts!')
    f.close()
    exit()

create_alert(canary)