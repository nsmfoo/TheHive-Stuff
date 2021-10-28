#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
import requests
from datetime import datetime
import time 
import json
from urllib.parse import urlparse

class ZscalerBlacklister(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.category_name = self.get_param('config.category_name', None, "Custom Category Name Missing")
        self.api_key = self.get_param('config.api_key', None, 'Zscaler API key is missing')
        self.base_uri = self.get_param('config.base_uri', None, 'Zscaler base URI is missing')
        self.username = self.get_param('config.username', None, 'Zscaler username is missing')
        self.password = self.get_param('config.password', None, 'Zscaler password is missing')
        self.config_name = self.get_param('config.config_name', None, 'ConfiguredName is missing')

    def add_to_category(self, url):

        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
             'User-Agent': 'Cortex-Responder'
        }
        session = requests.Session()

        api_key = self.api_key
        # Get JSESSIONID
        now = str(int(time.time() * 1000))
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        obfuscated_key = ""
        for i in range(0, len(n), 1):
            obfuscated_key += self.api_key[int(n[i])]
        for j in range(0, len(r), 1):
            obfuscated_key += self.api_key[int(r[j])+2]

        auth_payload = {
               "username": self.username,
               "password": self.password,
               "apiKey": obfuscated_key,
               "timestamp": int(now)
        }

        payload  = {
                      "configuredName" : self.config_name,
                      "superCategory": "USER_DEFINED",
                      "urls" : [url],
        }


        r = session.post(self.base_uri + '/api/v1/authenticatedSession', headers=self.headers, json=auth_payload)
        if r.status_code != 200:
            self.error("Authentication Error, code '{}'".format(r.status_code))
        s = session.put(self.base_uri + '/api/v1/urlCategories/' + self.category_name + '?action=ADD_TO_LIST', json.dumps(payload) , headers=self.headers)
        if s.status_code != 200:
            self.error("Unable to add item, code '{}'".format(s.status_code))
        else:
            s.close()
            return True

    def _strip_scheme(self,url):
        parsed = urlparse(url)
        scheme = "%s://" % parsed.scheme
        return parsed.geturl().replace(scheme, '', 1)
    
    def run(self):
        supported_types = ['domain', 'fqdn', 'url']
        Responder.run(self)
        
        data_type = self.get_param('data.dataType')
        if data_type in supported_types:
            item = self.get_param('data.data', None, 'No artifacts available')
  
            if data_type == 'domain':
                item = '.' + item

            if data_type == 'fqdn':
                pass #Remember that FQDN does not contain a schema like HTTP or HTTPS ...

            if data_type == 'url':
                item = self._strip_scheme(item)

            success = self.add_to_category(item)
            if success:
                    self.report({"message": "Blacklisted in Zscaler."})
            else:
                    self.error("Failed to commit changes to blacklist.")
        else:
           self.error('Data type is not supported by the responder.')

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='zscaler:blocked')]

if __name__ == '__main__':
        ZscalerBlacklister().run()
