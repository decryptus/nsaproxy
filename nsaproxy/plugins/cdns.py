# -*- coding: utf-8 -*-
"""cdns plugin"""

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

import cdnetworks
import json
import logging
import os

from cdnetworks.services.cdns import DNS_SERVERS
from dwho.adapters.redis import DWhoAdapterRedis
from dwho.classes.plugins import PLUGINS
from nsaproxy.classes.apis import NSAProxyApiBase, NSAProxyApiSync, APIS_SYNC
from sonicprobe import helpers


LOG = logging.getLogger('nsaproxy.plugins.cdns')

#logging.getLogger('requests').setLevel(logging.WARNING)


class NSAProxyCdnsPlugin(NSAProxyApiBase):
    PLUGIN_NAME = 'cdns'

    def safe_init(self):
        self.conn           = None

        if self.PLUGIN_NAME not in self.config['plugins']:
            return

        self.adapter_redis  = DWhoAdapterRedis(self.config, prefix = 'nsaproxy')

        if self.config['plugins'][self.PLUGIN_NAME].get('credentials'):
            cred = helpers.load_yaml_file(self.config['plugins'][self.PLUGIN_NAME]['credentials'])
            if not cred:
                raise ValueError("unable to read credentials")

            for k, v in cred['cdnetworks'].iteritems():
                os.environ[k.upper()] = v

        self.conn = cdnetworks.service('cdns')

        APIS_SYNC.register(NSAProxyApiSync(self.PLUGIN_NAME))

    def at_start(self):
        if self.PLUGIN_NAME in APIS_SYNC:
            self.start()

    def _get_soa_email(self, email, zoneid):
        ref_conf = self.config['plugins'][self.PLUGIN_NAME]

        r = email

        if '@' not in r:
            r = r.replace('.', '@', 1)

        if 'soa' not in ref_conf:
            return r

        if zoneid in ref_conf['soa'] \
           and ref_conf['soa'][zoneid].get('email_address'):
            return ref_conf['soa'][zoneid]['email_address']

        if 'default' in ref_conf['soa'] \
           and ref_conf['soa']['default'].get('email_address'):
            return ref_conf['soa']['default']['email_address']

        return r

    def _build_record_value(self, zoneid, xtype, content):
        r = {}

        if xtype == 'SOA':
            (r['value'],
             r['email'],
             r['serial_number'],
             r['refresh'],
             r['retry'],
             r['expire'],
             r['minmum']) = content.split(' ', 7)
            r['email'] = self._get_soa_email(r['email'].rstrip('.'), zoneid)
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

    def _merge_rrsets(self, zone, rrsets):
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
            return

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
            domains = self.conn.search_domains(zoneid)
            if not domains \
               or 'domains' not in domains \
               or not domains['domains'].get('domains'):
                raise LookupError("unable to find zone id: %r" % zoneid)
            self.adapter_redis.set_key(self._keyname_zone(zoneid),
                                       domains['domains']['domains'][0]['domain_id'])

        xid     = self.adapter_redis.get_key(self._keyname_zone(zoneid))
        if not xid:
            raise LookupError("unable to find zone id: %r" % zoneid)

        xid     = long(xid)
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
                changes.append({'action':      'purge',
                                'host_name':   name,
                                'record_type': rrset['type']})
                continue

            for record in rrset['records']:
                change = {'host_name':   name,
                          'ttl':         rrset.get('ttl') or 0,
                          'record_type': rrset['type']}

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
            r = self.conn.change_records(xid,
                                         changes,
                                         deploy_type = self.config['plugins'][self.PLUGIN_NAME].get('deployment'))
        self.adapter_redis.set_key(self._keyname_rrsets(zoneid),
                                   json.dumps(nrrsets))


if __name__ != "__main__":
    def _start():
        PLUGINS.register(NSAProxyCdnsPlugin())
    _start()
