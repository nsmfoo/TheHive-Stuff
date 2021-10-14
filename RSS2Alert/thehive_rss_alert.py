#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import sys
import json
import uuid
import re
import datetime
import feedparser
from urllib.parse import urlparse
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper

api = TheHiveApi('<TheHive URL>', '<TheHive API key>')

feed_list = open('feedlist.txt', 'r')

for x in feed_list:
    domain_name = urlparse(x).netloc
    # Get RSS stuff
    feed = feedparser.parse(x)
    feedo_entries = feed.entries
    for entry in feed.entries:
        article_title = entry.title
        article_link = entry.link
        try:
            if entry.published:
                article_published_at = entry.published
            elif entry.updated:
                article_published_at = entry.updated
            else:
                article_published_at = entry.pubDate
        except:
            continue
        #article_published_at_parsed = entry.published_parsed
        clean = re.compile('<.*?>')
        content = re.sub(clean, '', entry.summary)

        # Check post for certain keywords (check content instead.. keywords sucks)
        keywords = ['ransomware', '0-day', 'worm', 'APT', 'exploit', 'breach', 'hacked', 'CVE']
        y = 0
        try:
            for x in entry.tags:
             if any(x == entry.tags[y].term.lower() for x in keywords):
                sev = 2
             else:
                sev = 1
             y += 1
        except:
            sev = 1

        today_date = datetime.datetime.now()
        today = today_date.strftime("%a, %d %b %Y")
        if today in article_published_at:

            cve_data = re.findall('CVE-[0-9]{4}-[0-9]{5}', content, flags=re.IGNORECASE)

            artifacts = [
                AlertArtifact(dataType='cve', data=cve_data),
            ]

        # Prepare the Alert
            sourceRef = str(uuid.uuid4())[0:6]
            alert = Alert(title='New Alert',
                tlp=2,
                tags=['vuln_news', domain_name],
                description=content + " URL: "  + article_link,
                severity=sev,
                caseTemplate='News',
                type='rss-feed',
                source='rss_to_thehive',
                sourceRef=sourceRef,
                artifacts=artifacts)

        # Create the Alert
            id = None
            response = api.create_alert(alert)
            if response.status_code == 201:
                print(json.dumps(response.json(), indent=4, sort_keys=True))
                print('')
                id = response.json()['id']
            else:
                print('ko: {}/{}'.format(response.status_code, response.text))
                sys.exit(0)

feed_list.close()
