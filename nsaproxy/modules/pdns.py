# -*- coding: utf-8 -*-
# Copyright (C) 2018-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""nsaproxy.modules.pdns"""

import json
import logging
import time
import uuid

from copy import deepcopy

import requests

from six import itervalues, string_types

from dwho.classes.modules import DWhoModuleBase, MODULES
from sonicprobe import helpers
from sonicprobe.libs import network, urisup, xys
from sonicprobe.libs.moresynchro import ListLock, RWLock
from httpdis.ext.httpdis_json import HttpReqErrJson, HttpResponseJson

from ..classes.apis import NSAProxyApiObject, APIS_SYNC
from ..classes.common import DEFAULT_TTL, NSAProxyPDNSApiHelpers

LOG = logging.getLogger('nsaproxy.modules.pdns')


def validate_domain(domain, mask = network.MASK_DOMAIN):
    if not isinstance(domain, string_types) \
       or not domain \
       or domain[-1] != '.':
        return False

    return network.valid_host(domain[0:-1], mask)

def validate_ipaddr(ip_addr):
    return network.valid_host(ip_addr, network.MASK_IPV4_DOTDEC | network.MASK_IPV6)


xys.add_callback('pdns.domain', validate_domain)
xys.add_callback('pdns.ipaddr', validate_ipaddr)


class PDNSModule(DWhoModuleBase):
    MODULE_NAME     = 'pdns'

    LOCK            = RWLock()
    ZONELOCK        = ListLock()

    def __init__(self):
        DWhoModuleBase.__init__(self)

        self._helpers = None

    def init(self, config):
        DWhoModuleBase.init(self, config)

        self._helpers = NSAProxyPDNSApiHelpers(self.config)

        return self

    # pylint: disable-msg=attribute-defined-outside-init
    def safe_init(self, options):
        self.results      = {}
        self.lock_timeout = self.config['general']['lock_timeout']
        self.api_uri      = list(urisup.uri_help_split(self.config['general']['pdns']['api_uri']))
        self.api_key      = None

        if self.config['general']['pdns'].get('credentials'):
            cred = helpers.load_yaml_file(self.config['general']['pdns']['credentials'])
            if not cred:
                raise ValueError("unable to read credentials")
            if 'pdns' not in cred or not cred['pdns'].get('api_key'):
                raise ValueError("unable to find pdn api key")

            self.api_key = cred['pdns']['api_key']

    def _lock(self, endpoint, zone_id, lock_func = None):
        if not lock_func:
            lock_func = self.LOCK.acquire_read

        if endpoint == 'zones' and zone_id:
            zone_id = zone_id.rstrip('.')
            if self.ZONELOCK.try_acquire(zone_id):
                raise HttpReqErrJson(503, "unable to take ZONELOCK(%r)" % zone_id)

            return (self.ZONELOCK.release, [zone_id])

        if not lock_func(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for reading after %s seconds" % self.lock_timeout)

        return (self.LOCK.release, [])

    @staticmethod
    def _add_record(content):
        return {'content': content, 'disabled': False, 'set-prt': False}

    def _add_rrset(self, zone, domain_name, xtype, content, ttl = DEFAULT_TTL):
        if 'rrsets' not in zone:
            zone['rrsets'] = []

        for rrset in zone['rrsets']:
            if rrset['type'] != xtype:
                continue

            if rrset['name'].rstrip('.') != domain_name:
                continue

            rrset['records'] = [self._add_record(content)]
            return

        zone['rrsets'].append({'name': "%s." % domain_name,
                               'type': xtype,
                               'ttl': ttl,
                               'changetype': 'REPLACE',
                               'records': [self._add_record(content)]})

    @staticmethod
    def _replace_vars(key, xvars):
        if '%(' in key and ')s' in key:
            return key % xvars

        return key

    def _append_rrsets(self, zone, domain_name, rrsets):
        r = False

        if not isinstance(rrsets, list):
            return r

        if 'rrsets' not in zone:
            zone['rrsets'] = []

        for x in rrsets:
            rrset = deepcopy(x)
            names = rrset['name']

            if not isinstance(names, list):
                names = [names]

            for name in names:
                if name == '@':
                    rrset['name'] = "%s." % domain_name
                elif name == '*':
                    rrset['name'] = "*.%s." % domain_name
                elif name[-1] == '.':
                    rrset['name'] = "%s." % name.rstrip('.')
                else:
                    rrset['name'] = "%s.%s." % (name.rstrip('.'), domain_name)

                xvars = {'name': name,
                         'domain_name': domain_name}

                rrset['name'] = self._replace_vars(rrset['name'], xvars)
                rrset['ttl'] = int(rrset.get('ttl', DEFAULT_TTL))
                rrset['changetype'] = 'REPLACE'

                if rrset.get('records'):
                    for record in rrset['records']:
                        record['content'] = self._replace_vars(record.get('content') or '',
                                                               xvars)
                        record['disabled'] = bool(record.get('disabled') or False)

                if rrset.get('comments'):
                    for comment in rrset['comments']:
                        comment['content'] = self._replace_vars(comment.get('content') or '',
                                                                xvars)
                        comment['account'] = self._replace_vars(comment.get('account') or '',
                                                                xvars)

                zone['rrsets'].append(deepcopy(rrset))
                r = True

        return r

    def _fetch_zone(self, request, params, path = None):
        res = self._do_request('get', path or request.get_path(), params, None, request.get_headers())
        if not res.text:
            return None

        return res.json()

    def _check_api_key(self, request):
        api_key = request.headers.get('x-api-key') or self.api_key
        if not api_key:
            raise HttpReqErrJson("missing api key")
        request.headers['x-api-key'] = api_key

    def _do_request(self, method, path, params, payload, headers):
        uri    = list(self.api_uri)
        uri[2] = path or None

        h      = {}
        for k, v in headers.iteritems():
            if k.lower() != 'content-length':
                h[k.lower()] = v

        return getattr(requests, method.lower())(urisup.uri_help_unsplit(uri),
                                                 params  = params,
                                                 json    = payload,
                                                 headers = h)

    def _do_response(self, request, params = None, args = None, method = None):
        r =  self._do_request(method or request.get_method(), request.get_path(), params, args, request.get_headers())
        if not r.text:
            return HttpResponseJson(r.status_code)

        try:
            ret = r.json()
        except Exception:
            ret = {"message": r.text}

        return HttpResponseJson(r.status_code, ret)

    def _set_result(self, obj):
        self.results[obj.get_uid()] = obj

    def _get_results(self, uids):
        r = {'expected':   len(uids),
             'successful': [],
             'failed':     []}

        while r['expected'] > 0:
            for uid in uids:
                if uid not in self.results:
                    time.sleep(0.5)
                    continue

                res = self.results.pop(uid)
                if res.has_error():
                    r['failed'].append(res)
                    r['expected'] -= 1
                    LOG.warning("failed on call: %r. (errors: %r)", res.get_uid(), res.get_errors())
                else:
                    r['successful'].append(res)
                    r['expected'] -= 1
                    LOG.info("successful on call: %r. (result: %r)", res.get_uid(), res.get_result())

        return r

    def _refresh_apis(self, zone):
        for rrset in zone['rrsets']:
            rrset['changetype'] = 'REPLACE'

        return self._push_apis_sync('change_rrsets', {'id': zone['id']}, args = zone)

    def _push_apis_sync(self, endpoint, params, args = None, zone = None):
        r   = []
        xid = "%s" % uuid.uuid4()
        for api_sync in itervalues(APIS_SYNC):
            uid = "%s:%s" % (api_sync.name, xid)
            api_sync.qput(NSAProxyApiObject(api_sync.name, uid, endpoint, zone, params, args, self._set_result))
            r.append(uid)

        return r


    ENDPOINT_GET_QSCHEMA = xys.load("""
    server_id: !!str
    endpoint:  !!str
    id*:       !!str
    command*:  !~~enum(check,export)
    """)

    def api_endpoint_get(self, request):
        params = request.query_params()

        self._check_api_key(request)

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.ENDPOINT_GET_QSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command")

        (lock_release_func,
         lock_release_args) = self._lock(params['endpoint'],
                                         params.get('id'))

        try:
            return self._do_response(request, params)
        except HttpReqErrJson as e:
            raise
        except Exception as e:
            LOG.exception("%r", e)
        finally:
            lock_release_func(*lock_release_args)

        return None


    ENDPOINT_PUT_QSCHEMA = xys.load("""
    server_id: !!str
    endpoint:  !!str
    id:        !!str
    command*:  !~~enum(axfr-retrieve,notify,rectify)
    domain*:   !!str
    """)

    def api_endpoint_put(self, request):
        params = request.query_params()

        self._check_api_key(request)

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.ENDPOINT_PUT_QSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command")

        (lock_release_func,
         lock_release_args) = self._lock(params['endpoint'],
                                         params['id'])

        try:
            return self._do_response(request, params)
        except HttpReqErrJson as e:
            raise
        except Exception as e:
            LOG.exception("%r", e)
        finally:
            lock_release_func(*lock_release_args)

        return None


    ENDPOINT_POST_QSCHEMA = xys.load("""
    server_id: !!str
    endpoint:  !~~enum(zones)
    """)

    ENDPOINT_POST_PSCHEMA = xys.load("""
    nameservers?:  [ !~~callback(pdns.domain) ]
    masters?:      [ !~~callback(pdns.ipaddr) ]
    kind:          !~~ienum(native,master,primary,slave,secondary)
    name:          !~~callback(pdns.domain)
    account?:      !!str
    soa_edit_api?: !~~enum(DEFAULT,INCREASE,INCEPTION-INCREMENT,EPOCH,INCEPTION-EPOCH)
    """)

    def api_endpoint_post(self, request):
        params = request.query_params()
        args   = request.payload_params()

        self._check_api_key(request)

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type for query parameters")

        if not xys.validate(params, self.ENDPOINT_POST_QSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command for query parameters")

        if not isinstance(args, dict):
            raise HttpReqErrJson(400, "invalid arguments type for payload parameters")

        if not xys.validate(args, self.ENDPOINT_POST_PSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command payload parameters")

        (lock_release_func,
         lock_release_args) = self._lock(params['endpoint'],
                                         args['name'],
                                         self.LOCK.acquire_write)

        try:
            has_rrsets = False
            domain_name = args['name'].rstrip('.')

            if self.config['dns'].get('domains'):
                for domain in (domain_name, 'default'):
                    if not self.config['dns']['domains'].get(domain):
                        continue
                    rrsets = deepcopy(self.config['dns']['domains'][domain]['rrsets'])

                    has_rrsets = self._append_rrsets(args,
                                                     domain_name,
                                                     rrsets)

            uids = self._push_apis_sync('create_hosted_zone', params, args)
            if not uids:
                raise HttpReqErrJson(500, "unable to retrieve uids")

            res = self._get_results(uids)
            if res['failed']:
                raise HttpReqErrJson(409, "failed to synchronize on dns provider. (errors: %r)" % res['failed'])

            for ret in res['successful']:
                res = ret.get_result()
                if not res or 'nameservers' not in res:
                    continue

                if 'nameservers' not in args:
                    args['nameservers'] = []

                for nameserver in res['nameservers']:
                    args['nameservers'].append("%s." % nameserver.rstrip('.'))

            soa_content = self._helpers.build_soa_content(domain_name, args.get('nameservers'))
            if soa_content:
                has_rrsets = True
                self._add_rrset(args, domain_name, 'SOA', soa_content)

            r = self._do_response(request, None, args)
            if not r \
               or (not args.get('nameservers') \
                   and not has_rrsets):
                return r

            data = r.get_data()
            if data:
                data = json.loads(data)
                if data and 'id' in data:
                    self._refresh_apis(data)

            return r
        except HttpReqErrJson as e:
            raise
        except Exception as e:
            LOG.exception("%r", e)
        finally:
            lock_release_func(*lock_release_args)

        return None


    ENDPOINT_PATCH_QSCHEMA = xys.load("""
    server_id: !!str
    endpoint:  !~~enum(zones)
    id:        !!str
    """)

    ENDPOINT_PATCH_PSCHEMA = xys.load("""
    nameservers?:  [ !~~callback(pdns.domain) ]
    masters?:      [ !~~callback(pdns.ipaddr) ]
    kind?:         !~~ienum(native,primary,secondary,master,slave)
    name?:         !~~callback(pdns.domain)
    soa_edit_api?: !~~enum(INCEPTION-INCREMENT,EPOCH,INCEPTION-EPOCH)
    rrsets?:       !~~seqlen(0,9999)
      - comments?:
          - content:  !!str
          - account:  !!str
      - records:
          - content*: !!str
            disabled: !~~isBool
            set-prt?: !~~isBool
        changetype:   !~~enum(DELETE,REPLACE)
        type:    !~~enum(A,AAAA,ALIAS,CAA,CNAME,RCNAME,MX,NS,PTR,SOA,SPF,SRV,TXT)
        name:    !!str
        ttl?:    !~~uint
    """)

    def api_endpoint_patch(self, request):
        params = request.query_params()
        args   = request.payload_params()

        self._check_api_key(request)

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type for query parameters")

        if not xys.validate(params, self.ENDPOINT_PATCH_QSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command for query parameters")

        if not isinstance(args, dict):
            raise HttpReqErrJson(400, "invalid arguments type for payload parameters")

        if not xys.validate(args, self.ENDPOINT_PATCH_PSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command payload parameters")

        (lock_release_func,
         lock_release_args) = self._lock(params['endpoint'],
                                         params['id'],
                                         self.LOCK.acquire_write)

        try:
            if not args.get('rrsets'):
                return self._do_response(request, None, args)

            zone = self._fetch_zone(request, params)
            uids = self._push_apis_sync('change_rrsets', params, args, zone)
            if not uids:
                raise HttpReqErrJson(500, "unable to retrieve uids")

            res = self._get_results(uids)
            if res['failed']:
                raise HttpReqErrJson(409, "failed to synchronize on dns provider. (errors: %r)" % res['failed'])

            return self._do_response(request, None, args)
        except HttpReqErrJson as e:
            raise
        except Exception as e:
            LOG.exception("%r", e)
        finally:
            lock_release_func(*lock_release_args)

        return None


    ENDPOINT_DELETE_QSCHEMA = xys.load("""
    server_id: !!str
    endpoint:  !~~enum(zones)
    id:        !!str
    """)

    def api_endpoint_delete(self, request):
        params  = request.query_params()

        self._check_api_key(request)

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type for query parameters")

        if not xys.validate(params, self.ENDPOINT_DELETE_QSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command for query parameters")

        (lock_release_func,
         lock_release_args) = self._lock(params['endpoint'],
                                         params['id'],
                                         self.LOCK.acquire_write)

        try:
            uids = self._push_apis_sync('delete_hosted_zone', params)
            if not uids:
                raise HttpReqErrJson(500, "unable to retrieve uids")

            res = self._get_results(uids)
            if res['failed']:
                raise HttpReqErrJson(409, "failed to synchronize on dns provider. (errors: %r)" % res['failed'])

            return self._do_response(request)
        except HttpReqErrJson:
            raise
        except Exception as e:
            LOG.exception("%r", e)
        finally:
            lock_release_func(*lock_release_args)

        return None


    ENDPOINT_VALIDATE_QSCHEMA = xys.load("""
    server_id: !!str
    endpoint:  !!str
    id:        !~~callback(pdns.domain)
    """)
    def api_endpoint_validate(self, request):
        params = request.query_params()

        self._check_api_key(request)

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type for query parameters")

        if not xys.validate(params, self.ENDPOINT_VALIDATE_QSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command for query parameters")

        if not self.LOCK.acquire_read(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for reading after %s seconds" % self.lock_timeout)

        try:
            domain = params.pop('id').lower()

            r = self._do_response(request, method = 'GET')
            if not r:
                raise HttpReqErrJson(500, "unable to fetch domains list")

            data = r.get_data()
            if not data:
                raise HttpReqErrJson(500, "unable to fetch domains list")

            data = json.loads(data)
            if not isinstance(data, list):
                raise HttpReqErrJson(500, "unable to fetch domains list")

            if not data:
                return True

            for x in data:
                if x['name'] == domain:
                    raise HttpReqErrJson(409, "domain %r already exists" % domain)

            return True
        except HttpReqErrJson as e:
            raise
        except Exception as e:
            LOG.exception("%r", e)
        finally:
            self.LOCK.release()

        return False


if __name__ != "__main__":
    def _start():
        MODULES.register(PDNSModule())
    _start()
