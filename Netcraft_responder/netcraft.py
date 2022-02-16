#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
import requests
import json

class NetcraftPhishingSubmit(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.email = self.get_param('config.email', None, "Email address is missing")
        self.reason = self.get_param('config.reason')
        if self.reason == None:
           self.reason = "Phishing"

        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Cortex-Responder'
        }

    def submit(self, url):

        payload  = {
                   "email": self.email,
                   "reason": self.reason,
                   "urls": [{ "url": url }]
        }
        r = requests.post('https://report.netcraft.com/api/v3/report/urls', headers=self.headers, data=json.dumps(payload))

        if r.status_code != 200:
            self.error("Unable to add item, code '{}'".format(r.status_code))
        else:
            return True

    def run(self):
        supported_types = ['url']
        Responder.run(self)

        data_type = self.get_param('data.dataType')
        if data_type in supported_types:
            item = self.get_param('data.data', None, 'No artifacts available')
            success = self.submit(item)
            if success:
                  self.report({"message": "Submitted to Netcraft"})
            else:
                    self.error("Failed to submit")
        else:
           self.error('Data type is not supported by the responder.')

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='netcraft:submitted')]

if __name__ == '__main__':
       NetcraftPhishingSubmit().run()
