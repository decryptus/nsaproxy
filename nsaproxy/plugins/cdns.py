# -*- coding: utf-8 -*-
# Copyright (C) 2018-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""nsaproxy.plugins.cdns"""

import json
import logging
import os

from six import iteritems

from dwho.adapters.redis import DWhoAdapterRedis
from dwho.classes.plugins import PLUGINS
from sonicprobe import helpers

import cdnetworks
from cdnetworks.services.cdns import DNS_SERVERS

from ..classes.apis import NSAProxyApiBase, NSAProxyApiSync, APIS_SYNC


LOG = logging.getLogger('nsaproxy.plugins.cdns')

#logging.getLogger('requests').setLevel(logging.WARNING)


class NSAProxyCdnsPlugin(NSAProxyApiBase):
    PLUGIN_NAME = 'cdns'

    # pylint: disable-msg=attribute-defined-outside-init
    def safe_init(self):
        self.conn = None

        if not self.plugconf:
            return

        self.adapter_redis  = DWhoAdapterRedis(self.config, prefix = 'nsaproxy')

        if self.plugconf.get('credentials'):
            cred = helpers.load_yaml_file(self.plugconf['credentials'])
            if not cred:
                raise ValueError("unable to read credentials")

            for k, v in iteritems(cred['cdnetworks']):
                if v:
                    os.environ[k.upper()] = v

        self.conn = cdnetworks.service('cdns')

        APIS_SYNC.register(NSAProxyApiSync(self.PLUGIN_NAME))

    def at_start(self):
        if self.PLUGIN_NAME in APIS_SYNC:
            self.start()

    def _sanitize_email(self, zoneid, email):
        email = self._helpers.get_soa_email(zoneid, email)
        if not email:
            return None

        email = email.rstrip('.')

        if '@' not in email:
            email = email.replace('.', '@', 1)

        return email

    def _build_record_value(self, zoneid, xtype, content):
        r = {}

        if xtype == 'SOA':
            r = self._helpers.split_type_content(xtype, content)
            if not r:
                raise ValueError("invalid soa content: %r" % content)

            r['email'] = self._sanitize_email(zoneid, r['email'])
        elif xtype == 'MX':
            (r['data'], r['value']) = content.split(' ', 1)
        elif xtype == 'SRV':
            (r['priority'],
             r['weight'],
             r['port'],
             r['target']) = content.split(' ', 4)
            r['target'] = r['target'].rstrip('.')
        elif xtype == 'NS':
            r['value'] = content.rstrip('.')
        elif xtype == 'TXT' \
           and len(content) > 1 \
           and content[0] == '"' \
           and content[-1] == '"':
            r['value'] = content[1:-1]
        else:
            r['value'] = content

        return r

    @staticmethod
    def _merge_rrsets(zone, rrsets):
        if not zone or not zone.get('rrsets'):
            return rrsets

        r = []

        zrrsets = list(zone['rrsets'])

        for zrrset in zrrsets:
            if 'comments' in zrrset:
                del zrrset['comments']

            found = False
            for rrset in rrsets:
                if zrrset['name'] == rrset['name'] \
                   and zrrset['type'] == rrset['type']:
                    found = True
                    break

            if not found:
                zrrset['changetype'] = 'REPLACE'
                r.append(zrrset)

        return r + rrsets

    def _do_create_hosted_zone(self, obj):
        args   = obj.get_args()
        zoneid = args['name'].rstrip('.')

        if self._is_excluded_zone(zoneid):
            return None

        self.adapter_redis.set_key(self._keyname_zone(zoneid), '')

        return {'nameservers': DNS_SERVERS}

    def _do_delete_hosted_zone(self, obj):
        params = obj.get_params()
        zoneid = params['id'].rstrip('.')

        if self._is_excluded_zone(zoneid):
            return

        self.adapter_redis.del_key(self._keyname_zone(zoneid))
        self.adapter_redis.del_key(self._keyname_rrsets(zoneid))

    def _do_change_rrsets(self, obj):
        params  = obj.get_params()
        zoneid  = params['id'].rstrip('.')

        if self._is_excluded_zone(zoneid):
            return

        xid     = self.adapter_redis.get_key(self._keyname_zone(zoneid))
        if not xid:
            zones = self.conn.search_zones(zoneid)
            if not zones \
               or 'data' not in zones \
               or not zones['data'].get('results'):
                raise LookupError("unable to find zone id: %r" % zoneid)
            self.adapter_redis.set_key(self._keyname_zone(zoneid),
                                       zones['data']['results'][0]['zoneId'])

        xid     = self.adapter_redis.get_key(self._keyname_zone(zoneid))
        if not xid:
            raise LookupError("unable to find zone id: %r" % zoneid)

        xid     = int(xid)
        args    = obj.get_args()
        changes = []

        nrrsets = []
        rrsets  = self.adapter_redis.get_key(self._keyname_rrsets(zoneid)) or []
        if rrsets:
            rrsets = json.loads(rrsets)

        for rrset in self._merge_rrsets(obj.get_zone(), args['rrsets']):
            if self._is_excluded_record(zoneid, rrset['type'], rrset['name']):
                continue

            if rrset['name'].endswith(".%s." % zoneid):
                name = rrset['name'][:-(len(zoneid) + 2)]
            elif rrset['name'] == ("%s." % zoneid):
                name = '@'
            else:
                name = rrset['name']

            if rrset['changetype'] == 'REPLACE':
                action = 'upsert'
            else:
                action = rrset['changetype'].lower()

            if rrset['changetype'] == 'DELETE':
                changes.append({'action': 'purge',
                                'hostName': name,
                                'type': rrset['type']})
                continue

            for record in rrset['records']:
                change = {'hostName': name,
                          'ttl': rrset.get('ttl') or 0,
                          'type': rrset['type']}

                change.update(self._build_record_value(zoneid, rrset['type'], record['content']))
                nrrsets.append(change.copy())

                if not self._is_in_cache(rrsets, change):
                    change['action'] = action
                    changes.append(change)

        if rrsets and nrrsets:
            for record in rrsets:
                if not self._is_in_cache(nrrsets, record):
                    record['action'] = 'delete'
                    changes.append(record)

        if changes:
            self.conn.change_records(xid,
                                     changes,
                                     deployment = self.plugconf.get('deployment'),
                                     force      = True)
        self.adapter_redis.set_key(self._keyname_rrsets(zoneid),
                                   json.dumps(nrrsets))


if __name__ != "__main__":
    def _start():
        PLUGINS.register(NSAProxyCdnsPlugin())
    _start()
