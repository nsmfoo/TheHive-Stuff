#!/usr/bin/env python3
# encoding: utf-8

import json
import requests
import os
from cortexutils.analyzer import Analyzer

class Rapid7Analyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.url = self.get_param('config.url', None, 'Rapid7 portal URL is missing')
        self.api_key = self.get_param('config.api_key', None, 'Rapid7 API key is missing')

      # Hardcoded because ...
      # os.environ['no_proxy'] = 'XXXX'

    def summary(self, raw):

        taxonomies = []
        namespace = "Rapid7"
        predicate = "RiskScore"
        level = "info"

        value = raw['result']['host'].get('riskscore')

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
          if self.data_type == 'ip' or self.data_type == 'hostname' or self.data_type == 'fqdn':
             host = self.get_param('data', None, 'Data is missing')

             r7_url = self.url + '/api/3/assets/search'
             if self.data_type == 'ip':
                data = '{ "match": "any", "filters": [ { "field": "ip-address", "operator": "is", "value": "' + host + '" } ]}'
             else:
                data = '{ "match": "any", "filters": [ { "field": "host-name", "operator": "is", "value": "' + host + '" } ]}'

             headers = {'Content-type': 'application/json', 'Authorization': 'Basic ' + self.api_key + ''}
             r7 = requests.post(r7_url, data=data, headers=headers)
             vuln_data = r7.json()

             host_info = []

             try:
                for key in vuln_data['resources']:
                        host_info.append(key['id'])
                        host_info.append(key['os'])
                        host_info.append(key['riskScore'])
                        host_info.append(host)
             except:
                 host_info.append('None')

             if not host_info or 'None' in host_info[1]:
                self.error('Host or IP not found in the R7 dataset')
             else:
                r7_url = self.url + '/api/3/assets/' + str(host_info[0]) + '/vulnerabilities?size=100'
                r7 = requests.get(r7_url, headers=headers)
                vuln_data = r7.json()

             vuln_id = []
             for key in vuln_data['resources']:
                 vuln_id.append(key['id'])

             vuln_data_result = {}
             for key in vuln_id:
                 r7_url = self.url + '/api/3/vulnerabilities/' + str(key) + ''
                 r7 = requests.get(r7_url, headers=headers)
                 vuln_data = r7.json()
                 if vuln_data['cvss']['v2'].get('score') != 0:
                    vuln_data_result[key] = {'title': vuln_data['title'], 'cvss': vuln_data['cvss']['v2'].get('score')}

             vuln_data_result['host'] = {'hostname': host_info[3], 'os': host_info[1], 'riskscore': int(host_info[2])}
             #vuln_data_result = sorted(vuln_data_result.items(), key = lambda x: x[1]['cvss'], reverse=True)
             self.report({'result': vuln_data_result})
          else:
             data = self.get_param('data', None, 'Data is missing')

if __name__ == '__main__':
    Rapid7Analyzer().run()