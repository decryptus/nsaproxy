# -*- coding: utf-8 -*-
"""r53 plugin"""

__author__  = "Adrien DELLE CAVE"
__license__ = """
    Copyright (C) 2018  fjord-technologies

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA..
"""

import boto3
import json
import logging
import os

from dwho.adapters.redis import DWhoAdapterRedis
from dwho.classes.plugins import PLUGINS
from nsaproxy.classes.apis import NSAProxyApiBase, NSAProxyApiSync, APIS_SYNC
from sonicprobe import helpers


LOG = logging.getLogger('nsaproxy.plugins.r53')

#logging.getLogger('requests').setLevel(logging.WARNING)


class NSAProxyR53Plugin(NSAProxyApiBase):
    PLUGIN_NAME = 'r53'

    def safe_init(self):
        self.conn           = None

        if self.PLUGIN_NAME not in self.config['plugins']:
            return

        self.adapter_redis  = DWhoAdapterRedis(self.config, prefix = 'nsaproxy')

        if self.config['plugins'][self.PLUGIN_NAME].get('credentials'):
            cred = helpers.load_yaml_file(self.config['plugins'][self.PLUGIN_NAME]['credentials'])
            if not cred:
                raise ValueError("unable to read credentials")

            for k, v in cred['route53'].iteritems():
                os.environ[k.upper()] = v

        self.conn = boto3.client('route53')

        APIS_SYNC.register(NSAProxyApiSync(self.PLUGIN_NAME))

    def at_start(self):
        if self.PLUGIN_NAME in APIS_SYNC:
            self.start()

    def _find_domain(self, name):
        res = self.conn.list_hosted_zones_by_name(DNSName  = name,
                                                  MaxItems = '1')
        if not res or not res['HostedZones']:
            return

        for row in res['HostedZones']:
            if row['Name'].rstrip('.') == name:
                return row

    def _do_create_hosted_zone(self, obj):
        args   = obj.get_args()
        zoneid = args['name'].rstrip('.')

        if self._is_excluded_zone(zoneid):
            return

        res    = self._find_domain(zoneid)
        if res:
            self.adapter_redis.set_key(self._keyname_zone(zoneid),
                                       res['Id'])
        else:
            r = self.conn.create_hosted_zone(Name            = args['name'],
                                             CallerReference = obj.get_uid())
            self.adapter_redis.set_key(self._keyname_zone(zoneid),
                                       r['HostedZone']['Id'])

            if 'DelegationSet' in r and 'NameServers' in r['DelegationSet']:
                return {'nameservers': r['DelegationSet']['NameServers']}

    def _do_delete_hosted_zone(self, obj):
        params = obj.get_params()
        zoneid = params['id'].rstrip('.')

        if self._is_excluded_zone(zoneid):
            return

        xid    = self.adapter_redis.get_key(self._keyname_zone(zoneid))
        if not xid:
            res = self._find_domain(zoneid)
            if res:
                xid = res['Id']
            else:
                LOG.warning("unable to find zone id: %r" % zoneid)
                return

        self.conn.delete_hosted_zone(Id = xid)

        self.adapter_redis.del_key(self._keyname_zone(zoneid))
        self.adapter_redis.del_key(self._keyname_rrsets(zoneid))

    def _do_change_rrsets(self, obj):
        params  = obj.get_params()
        zoneid  = params['id'].rstrip('.')

        if self._is_excluded_zone(zoneid):
            return

        xid     = self.adapter_redis.get_key(self._keyname_zone(zoneid))
        if not xid:
            res = self._find_domain(zoneid)
            if not res:
                raise LookupError("unable to find zone id: %r" % zoneid)

            xid = res['Id']
            self.adapter_redis.set_key(self._keyname_zone(zoneid),
                                       xid)

        args    = obj.get_args()
        changes = {'Comment': '',
                   'Changes': []}

        nrrsets = []
        rrsets  = self.adapter_redis.get_key(self._keyname_rrsets(zoneid)) or []
        if rrsets:
            rrsets = json.loads(rrsets)

        for rrset in args['rrsets']:
            if self._is_excluded_record(zoneid, rrset['type'], rrset['name']):
                continue

            change = {'ResourceRecordSet': {'Name': rrset['name'],
                                            'TTL':  rrset.get('ttl') or 0,
                                            'Type': rrset['type'],
                                            'ResourceRecords': []}}

            if rrset['changetype'] == 'DELETE':
                res = self.conn.list_resource_record_sets(HostedZoneId    = xid,
                                                          StartRecordName = rrset['name'],
                                                          StartRecordType = rrset['type'],
                                                          MaxItems        = '1')
                if not res or not res['ResourceRecordSets']:
                    continue

                change['Action'] = rrset['changetype']
                change['ResourceRecordSet']['ResourceRecords'] = res['ResourceRecordSets'][0]['ResourceRecords']
                change['ResourceRecordSet']['TTL'] = res['ResourceRecordSets'][0]['TTL']

                changes['Changes'].append(change)
            else:
                if rrset['changetype'] == 'REPLACE':
                    action = 'UPSERT'
                else:
                    action = rrset['changetype']

                for record in rrset['records']:
                    change['ResourceRecordSet']['ResourceRecords'].append({'Value': record['content']})

                if not change['ResourceRecordSet']['ResourceRecords']:
                    continue

                nrrsets.append(change.copy())

                if not self._is_in_cache(rrsets, change):
                    change['Action'] = action
                    changes['Changes'].append(change)

        if changes['Changes']:
            r = self.conn.change_resource_record_sets(HostedZoneId = xid,
                                                      ChangeBatch  = changes)

        self.adapter_redis.set_key(self._keyname_rrsets(zoneid),
                                   json.dumps(nrrsets))


if __name__ != "__main__":
    def _start():
        PLUGINS.register(NSAProxyR53Plugin())
    _start()
