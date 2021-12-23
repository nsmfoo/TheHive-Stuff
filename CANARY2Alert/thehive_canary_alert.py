#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
import requests
import sys
import json
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper

def create_alert(canary):
    i= 0
    canary_data = []
    labels = ['Incident date','Flock','Canary Name','AttackType','Targeted Canary IP','Targeted Canary Port','Attacker IP','Attacker Hostname','Attacker Src Port']
    label_len = len(str(labels))
    ii = 0
    label_padd = ''
    while ii < label_len:
        label_padd = label_padd + '-'
        ii += 1
    while i < 9:
        canary_data.append('**' + labels[i] + ':** ' + str(canary[i]) + '\n\n')
        i += 1
    # For canary tokens include extra data
    if canary[3] == 'Canarytoken triggered':
        canary_data.append('**Memo: **'+ canary[10] +'\n\n')
    # Handle the event data
    # The header
    for event in canary[9]:
        for y in event.keys():
            canary_data.append('|'+ str(y).lower())
        canary_data.append('|\n|' + str(label_padd) + '|\n')
        # The content
        if canary[3] == 'Canarytoken triggered':
            for z in event.values():
                if isinstance(z, dict):
                    zz_top = []
                    for zz_k,zz_v in z.items():
                        zz_top.append(''.join(str(zz_k) + ': ' + str(zz_v)))
                    canary_data.append('|' + ' '.join(zz_top))
                else:
                    canary_data.append('|'+ str(z))
            canary_data.append('|\n\n')
        else:
            for z in event.values():
                canary_data.append('|'+ str(z))
            canary_data.append('|\n\n')

    description = ''.join(canary_data)
    artifacts = [
      AlertArtifact(dataType='ip', data=str(canary[6])),
    ]

    # Prepare the Alert
    sourceRef = str(uuid.uuid4())[0:6]
    alert = Alert(title='New Alert',
           tlp=3,
           tags=['canary_alert', 'attack_type=' + str(canary[3])],
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

# General settings
canary_base_url = 'https://<XXXXXX>.canary.tools/api/v1/'
api = TheHiveApi('<TheHive-URL>', '<API-KEY>')
token = '<CANARY TOKEN>'

# Impossible to write a script without a ascii banner..
print("""
                              .*******************.
                        ********************************     ((((((
                    /***********************************  (((((((((((
                 **************************************   ((((((((((((
               ****************************************   ((((((((((((
             *******************************************    ((((((((
           ************************************************          #
          *************************/         **************************
         ***********************                  **********************
        *********************/                            ***************
       *********************                        *********************#
       ********************                       ************************
       ******************(                       *************************
      /******************                        *************************
       *****************                        **************************
       *************                            **************************
       ***********                              **************************
        *******                                  ************************
         ****,                                   ***********************
          *                                      **********************
                                                 ********************(
                    Canary2TheHive                      Mikael Keri
""")

# Retrive all new alerts
url = canary_base_url + 'incidents/unacknowledged'
payload = {
        'auth_token': token,
        }

r = requests.get(url, params=payload)
result = r.json()

print('Working ...')

for flock in result['incidents']:
    canary = []
    canary.append(flock['description'].get('created_std'))
    canary.append(flock['description'].get('flock_name'))
    canary.append(flock['description'].get('name'))
    canary.append(flock['description'].get('description'))
    canary.append(flock['description'].get('dst_host'))
    canary.append(flock['description'].get('dst_port'))
    canary.append(flock['description'].get('src_host'))
    canary.append(flock['description'].get('src_host_reverse'))
    canary.append(flock['description'].get('src_port'))
    canary.append(flock['description'].get('events'))
    canary.append(flock['description'].get('memo'))

    # Retrive the incident ID
    int_id = flock['id']

    # Acknowledge the alert, keep the portal clean
    url_ack = canary_base_url + 'incident/acknowledge'
    payload_ack = {
          'auth_token': token,
          'incident':  int_id
    }
    ack = requests.post(url_ack, params=payload_ack)
    ack_result = ack.json()
    if ack_result['result'] == 'success':
       print('incident acknowledged')
    else:
       print('unable to acknowledge incident :/')

    create_alert(canary)
    time.sleep(3)
print('Done')