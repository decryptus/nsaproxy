# -*- coding: utf-8 -*-
# Copyright (C) 2018-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""nsaproxy.classes.common"""

import logging
import re

LOG = logging.getLogger('nsaproxy.classes.common')

DEFAULT_TTL = 300

RRSET_TYPES_SPLIT = {
    'SOA': re.compile(r'^\s*(?P<value>[a-zA-Z0-9_-][a-zA-Z0-9\._-]+[a-z]\.)\s+' +
                      r'(?P<email>[a-zA-Z0-9_-][a-zA-Z0-9\._-]+[a-z]\.)\s+' +
                      r'(?P<serial_number>[0-9]+)\s+(?P<refresh>[0-9]+)\s+' +
                      r'(?P<retry>[0-9]+)\s+(?P<expire>[0-9]+)\s+(?P<minmum>[0-9]+)\s*$').match}


class NSAProxyPDNSApiHelpers(object):
    def __init__(self, config, plugconf = None):
        self.config   = config
        self.plugconf = plugconf

    @staticmethod
    def split_type_content(xtype, content):
        m = RRSET_TYPES_SPLIT[xtype](content)
        if not m:
            return None

        return m.groupdict()

    @staticmethod
    def _cfg_soa_content(zoneid, config):
        if not config:
            return None

        for x in (zoneid, 'default'):
            if x in config:
                return config[x].get('content') or None

        return None

    @staticmethod
    def _cfg_soa_email(zoneid, config):
        if not config:
            return None

        for x in (zoneid, 'default'):
            if x in config:
                return config[x].get('email_address') or None

        return None

    def get_soa_content(self, zoneid):
        if self.config['dns'].get('soa'):
            r = self._cfg_soa_content(zoneid, self.config['dns']['soa'])
            if r:
                return r

        return None

    def get_soa_email(self, zoneid, email = None):
        r = self._cfg_soa_email(zoneid, self.plugconf)
        if r:
            return r

        if self.config['dns'].get('soa'):
            r = self._cfg_soa_email(zoneid, self.config['dns']['soa'])
            if r:
                return r

        return email

    def build_soa_content(self, zoneid, nameservers = None):
        content = self.get_soa_content(zoneid)
        if not content:
            return None

        xvars = {}

        if '%(email_address)' in content:
            email = self.get_soa_email(zoneid)
            if not email:
                return None

            xvars['email_address'] = "%s." % email.lower().replace('@', '.').rstrip('.')

        if '%(nameserver.' in content:
            if not nameservers:
                return None

            for i, nameserver in enumerate(nameservers):
                xvars["nameserver.%d" % i] = nameserver.lower()

        if xvars:
            content = content % xvars

        if not self.split_type_content('SOA', content):
            return False

        return content
