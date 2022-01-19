# -*- coding: utf-8 -*-
# Copyright (C) 2018-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""nsaproxy.plugins.r53"""

import json
import logging
import os
import re

from copy import deepcopy

import boto3

from six import iteritems

from dwho.adapters.redis import DWhoAdapterRedis
from dwho.classes.plugins import PLUGINS
from sonicprobe import helpers

from ..classes.apis import NSAProxyApiBase, NSAProxyApiSync, APIS_SYNC


LOG = logging.getLogger('nsaproxy.plugins.r53')

RE_COMMENT_TAGS_FINDALL = re.compile(r'(\w+=\w+)').findall
RE_COMMENT_TAGS = {'ContinentCode':
                     {'parent': 'GeoLocation',
                      'regex': re.compile(r'CONC=(?P<ContinentCode>[A-Z]{2})$').match,
                      'sanitize': str},
                   'CountryCode':
                     {'parent': 'GeoLocation',
                      'regex': re.compile(r'COYC=(?P<CountryCode>[A-Z]{1,2}|default)$').match,
                      'sanitize': lambda x: '*' if x == 'default' else x},
                   'EvaluateTargetHealth':
                     {'parent': 'AliasTarget',
                      'regex': re.compile(r'^ETH=(?P<EvaluateTargetHealth>[01])$').match,
                      'sanitize': helpers.boolize},
                   'HostedZoneId':
                     {'parent': 'AliasTarget',
                      'regex': re.compile(r'^HZI=(?P<HostedZoneId>[A-Z0-9]{13,14})$').match,
                      'sanitize': str},
                   'SetIdentifier':
                     {'parent': None,
                      'regex': re.compile(r'^ID=(?P<SetIdentifier>[a-zA-Z0-9]+)$').match,
                      'sanitize': str}}

RRSET_CONTENT_KEYS = ('AliasTarget',
                      'Failover',
                      'GeoLocation',
                      'HealthCheckId',
                      'MultiValueAnswer',
                      #'Name',
                      'ResourceRecords',
                      'SetIdentifier',
                      'Region',
                      'TrafficPolicyInstanceId',
                      'TTL',
                      #'Type',
                      'Weight')

RRSET_TYPES_NODEL = ('NS', 'SOA')

#logging.getLogger('requests').setLevel(logging.WARNING)


class NSAProxyR53Plugin(NSAProxyApiBase):
    PLUGIN_NAME = 'r53'

    # pylint: disable-msg=attribute-defined-outside-init
    def safe_init(self):
        self.conn           = None

        if self.PLUGIN_NAME not in self.config['plugins']:
            return

        self.adapter_redis  = DWhoAdapterRedis(self.config, prefix = 'nsaproxy')

        if self.plugconf.get('credentials'):
            cred = helpers.load_yaml_file(self.plugconf['credentials'])
            if not cred:
                raise ValueError("unable to read credentials")

            for k, v in iteritems(cred['route53']):
                os.environ[k.upper()] = v

        self.conn = boto3.client('route53')

        APIS_SYNC.register(NSAProxyApiSync(self.PLUGIN_NAME))

    def at_start(self):
        if self.PLUGIN_NAME in APIS_SYNC:
            self.start()

    @staticmethod
    def _tags_from_comment(comment):
        r = {}

        if not comment.get('content'):
            return r

        tags = RE_COMMENT_TAGS_FINDALL(comment['content'])
        if not tags:
            return r

        for tag in tags:
            for k, v in iteritems(RE_COMMENT_TAGS):
                m = v['regex'](tag)
                if not m:
                    continue

                if not v.get('parent'):
                    r[k] = v['sanitize'](m.group(1))
                    continue

                if v['parent'] not in r:
                    r[v['parent']] = {}
                r[v['parent']][k] = v['sanitize'](m.group(1))

        return r

    @staticmethod
    def _allow_rrset(zoneid, rrset):
        if rrset['type'] == 'NS' \
           and rrset['changetype'] == 'DELETE' \
           and rrset['name'].rstrip('.') == zoneid:
            return False

        return True

    @staticmethod
    def _get_rrset_obj(rtype, rrset):
        if rrset['type'] != 'ALIAS':
            return {'ResourceRecordSet': {'Name': rrset['name'],
                                          'TTL':  rrset.get('ttl') or 0,
                                          'Type': rtype,
                                          'ResourceRecords': []}}

        return {'ResourceRecordSet': {'Name': rrset['name'],
                                      'AliasTarget':
                                        {'DNSName': None,
                                         'HostedZoneId': None,
                                         'EvaluateTargetHealth': False},
                                      'Type': rtype}}


    @staticmethod
    def _init_changes_obj():
        return {'Comment': '',
                'Changes': []}

    def _find_domain(self, name):
        res = self.conn.list_hosted_zones_by_name(DNSName  = name,
                                                  MaxItems = '1')
        if not res or not res['HostedZones']:
            return None

        for row in res['HostedZones']:
            if row['Name'].rstrip('.') == name:
                return row

        return None

    def _do_create_hosted_zone(self, obj):
        args   = obj.get_args()
        zoneid = args['name'].rstrip('.')

        if self._is_excluded_zone(zoneid):
            return None

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

        return None

    def _do_delete_all_rrsets(self, xid):
        res = self.conn.list_resource_record_sets(HostedZoneId = xid)
        if not res or not res['ResourceRecordSets']:
            return

        changes = self._init_changes_obj()

        for record in res['ResourceRecordSets']:
            if record['Type'] in RRSET_TYPES_NODEL:
                continue

            changes['Changes'].append({'Action': 'DELETE',
                                       'ResourceRecordSet': record})

        if changes['Changes']:
            self.conn.change_resource_record_sets(HostedZoneId = xid,
                                                  ChangeBatch  = changes)
            if res['IsTruncated']:
                self._do_delete_all_rrsets(xid)

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
                LOG.warning("unable to find zone id: %r", zoneid)
                return

        try:
            self.conn.delete_hosted_zone(Id = xid)
        except self.conn.exceptions.NoSuchHostedZone:
            pass
        except self.conn.exceptions.HostedZoneNotEmpty:
            self._do_delete_all_rrsets(xid)

        try:
            self.conn.delete_hosted_zone(Id = xid)
        except self.conn.exceptions.NoSuchHostedZone:
            pass

        self.adapter_redis.del_key(self._keyname_zone(zoneid))
        self.adapter_redis.del_key(self._keyname_rrsets(zoneid))

    def _add_rrset(self, action, changes, rtype, rrset, rrsets, nrrsets):
        change = self._get_rrset_obj(rtype, rrset)

        for record in rrset['records']:
            rec = {'Value': record['content']}

            if rtype == 'TXT':
                if rec not in change['ResourceRecordSet']['ResourceRecords']:
                    change['ResourceRecordSet']['ResourceRecords'].append(rec)
            else:
                change['ResourceRecordSet']['ResourceRecords'].append(rec)

        if not change['ResourceRecordSet'].get('ResourceRecords'):
            return

        nrrsets.append(change.copy())

        if not self._is_in_cache(rrsets, change):
            change['Action'] = action
            changes['Changes'].append(change)

    def _add_aliases_rrset(self, action, changes, rtype, rrset, rrsets, nrrsets):
        for i, record in enumerate(rrset['records']):
            change = self._get_rrset_obj(rtype, rrset)

            if not rrset.get('comments') or len(rrset['comments']) < i:
                raise ValueError("missing comments for ALIAS entry: %r" % record['content'])

            tags = self._tags_from_comment(rrset['comments'][i])
            if not tags or not tags.get('AliasTarget') or not tags['AliasTarget'].get('HostedZoneId'):
                raise ValueError("missing HostedZoneId tag for ALIAS entry: %r" % record['content'])

            change['ResourceRecordSet'] = helpers.merge(tags, change['ResourceRecordSet'])
            change['ResourceRecordSet']['AliasTarget']['DNSName'] = record['content']

            nrrsets.append(change.copy())

            if not self._is_in_cache(rrsets, change):
                change['Action'] = action
                changes['Changes'].append(change)

    def _del_rrset(self, xid, changes, rtype, rrset):
        change = self._get_rrset_obj(rtype, rrset)

        if rrset.get('records'):
            max_items = str(len(rrset['records']))
        else:
            max_items = '1'

        res = self.conn.list_resource_record_sets(HostedZoneId    = xid,
                                                  StartRecordName = rrset['name'],
                                                  StartRecordType = rtype,
                                                  MaxItems        = max_items)
        if not res or not res['ResourceRecordSets']:
            return

        change['Action'] = 'DELETE'

        for record in res['ResourceRecordSets']:
            if record['Type'] != rtype or record['Name'] != rrset['name']:
                continue

            nchange = deepcopy(change)
            for x in RRSET_CONTENT_KEYS:
                if x in record:
                    nchange['ResourceRecordSet'][x] = record[x]

            changes['Changes'].append(nchange)

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
        changes = self._init_changes_obj()

        nrrsets = []
        rrsets  = self.adapter_redis.get_key(self._keyname_rrsets(zoneid)) or []
        if rrsets:
            rrsets = json.loads(rrsets)

        for rrset in args['rrsets']:
            if self._is_excluded_record(zoneid, rrset['type'], rrset['name']) \
               or not self._allow_rrset(zoneid, rrset):
                continue

            if rrset['type'] != 'ALIAS':
                rtype = rrset['type']
            else:
                rtype = 'A'

            if rrset['changetype'] == 'DELETE':
                self._del_rrset(xid, changes, rtype, rrset)
            else:
                if rrset['changetype'] == 'REPLACE':
                    action = 'UPSERT'
                else:
                    action = rrset['changetype']

                if rrset['type'] != 'ALIAS':
                    self._add_rrset(action, changes, rtype, rrset, rrsets, nrrsets)
                else:
                    self._add_aliases_rrset(action, changes, rtype, rrset, rrsets, nrrsets)

        if changes['Changes']:
            self.conn.change_resource_record_sets(HostedZoneId = xid,
                                                  ChangeBatch  = changes)

        self.adapter_redis.set_key(self._keyname_rrsets(zoneid),
                                   json.dumps(nrrsets))


if __name__ != "__main__":
    def _start():
        PLUGINS.register(NSAProxyR53Plugin())
    _start()
