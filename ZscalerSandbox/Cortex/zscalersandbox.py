#!/usr/bin/env python3
# encoding: utf-8

import requests
import json
import time
import hashlib
import io
import pyzipper
from urllib.parse import urlparse
from os.path import basename
from cortexutils.analyzer import Analyzer
import pprint

class ZscalerSandboxAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.api_key', None, 'Zscaler API key is missing')
        self.base_uri = self.get_param('config.base_uri', None, 'Zscaler base URI is missing')
        self.username = self.get_param('config.username', None, 'Zscaler username is missing')
        self.password = self.get_param('config.password', None, 'Zscaler password is missing')
        self.sandbox_uri = self.get_param('config.sandbox_uri', None, 'Zscaler sandbox URI is missing')
        self.sandbox_token = self.get_param('config.sandbox_token', None, 'Zscaler sandbox token is missing')
        self.zip_pw = self.get_param('config.zip_pw', None, 'Default password for Zip files')

        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Cortex-Analyzer'
        }
        # The time Zscaler says it should take ...
        self.timeout = 600

        self.session = requests.Session()

    def summary(self, raw):
        taxonomies = []
        namespace = "ZscalerSandbox"

        value = "{}/100".format(raw['result']['Full Details']['Classification'].get('Score'))

        classification = raw['result']['Full Details']['Classification'].get('Type')

        if classification == "MALICIOUS":
            verdict = "malicious"
        elif classification == "SUSPICIOUS":
            verdict = "suspicious"
        else:
            verdict = "safe"

        taxonomies.append(self.build_taxonomy(
        verdict,
        namespace,
        'Score',
        value
        ))

        return {"taxonomies": taxonomies}

    def perform_auth(self):

            # Get JSESSIONID
            now = str(int(time.time() * 1000))
            n = now[-6:]
            r = str(int(n) >> 1).zfill(6)
            obfuscated_key = ""
            for i in range(0, len(n), 1):
                obfuscated_key += self.api_key[int(n[i])]
            for j in range(0, len(r), 1):
                obfuscated_key += self.api_key[int(r[j])+2]

            payload = {
                "username": self.username,
                "password": self.password,
                "apiKey": obfuscated_key,
                "timestamp": int(now)
            }

            r = self.session.post(self.base_uri + '/api/v1/authenticatedSession', headers=self.headers, json=payload)

            return

    def check_quota(self):

            s = self.session.get(self.base_uri + '/api/v1/sandbox/report/quota', headers=self.headers)
            response = s.json()
            for x in response:
                if x['unused'] == 0:
                    self.error("Your quota is filled (try again tomorrow)")
            return

    def file_check(self, filename, filepath):

        self.perform_auth()
        self.check_quota()

        cal_hash = hashlib.md5()
        # Beware of redundant code below ... "will fix later"
        if pyzipper.is_zipfile(filepath):
            with pyzipper.AESZipFile(filepath) as zf:
                for zinfo in zf.infolist():
                    files = zf.namelist()
                    is_encrypted = zinfo.flag_bits & 0x1
                    # As the recpient is unable to handle pw protected zip files, we need to unzip it before submit
                    if is_encrypted:
                        zf.setpassword(self.zip_pw.encode('utf-8'))
                        for x in files:
                            sample = zf.read(x)
                            cal_hash.update(sample)
                            hash_result = cal_hash.hexdigest()
                            submit = self.submit_sample(sample, hash_result)
                    # Please note that zip archives that are not pw protected are not unzipped before submit
                    else:
                         with open(filepath, "rb") as samplef:
                            sample = samplef.read()
                            cal_hash.update(sample)
                            hash_result = cal_hash.hexdigest()
                            submit = self.submit_sample(sample, hash_result)
        else:
           with open(filepath, "rb") as samplef:
               sample = samplef.read()
               cal_hash.update(sample)
               hash_result = cal_hash.hexdigest()
               submit = self.submit_sample(sample, hash_result)
        return submit


    def submit_sample(self, sample, hash_result):

         # First attempt. check if the file is already analyzed
         f = self.session.get(self.base_uri + '/api/v1/sandbox/report/' + hash_result + '?details=full', headers=self.headers)
         response = f.json()

         if 'unknown' not in response['Full Details']:
             result = response
         else:
             headers_sub = {
                  "Content-Type":"application/binary",
             }

             e = self.session.post(self.sandbox_uri + '/zscsb/submit?force=1&api_token=' + self.sandbox_token, data=sample, headers=headers_sub)
             response = e.json()
             if e.status_code != 200:
                  self.error("Something went wrong ...")
             else:
                 x = 0
                 response['Full Details'] = "unknown"
                 # Sadly it does not really take 10 minutes to finalize (in most cases), here I will try 3 x "timeout value" and then give up. You can always re-submit. oh yea, each lookup deducts from the daily quota ...
                 while x < 3 and 'unknown' in response['Full Details']:
                       f = self.session.get(self.base_uri + '/api/v1/sandbox/report/' + hash_result + '?details=full', headers=self.headers)
                       response = f.json()
                       x += 1
                       time.sleep(self.timeout)
                 else:
                    if 'unknown' in response['Full Details']:
                        self.error("Unable to finalize the analyse in time, please try again")
                    else:
                        result = response
         return result

    def run(self):
        Analyzer.run(self)

        if self.data_type == 'file':
           filepath = self.get_param('file', None, 'File is missing')
           filename = self.get_param('filename', basename(filepath))
           result = self.file_check(filename, filepath)

           self.report({'result': result})

if __name__ == '__main__':
    ZscalerSandboxAnalyzer().run()
