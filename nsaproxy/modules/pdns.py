# -*- coding: utf-8 -*-
"""pdns module"""

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

import json
import logging
import requests
import time
import uuid

from dwho.classes.modules import DWhoModuleBase, MODULES
from nsaproxy.classes.apis import NSAProxyApiObject, APIS_SYNC
from sonicprobe import helpers
from sonicprobe.libs import network, urisup, xys
from sonicprobe.libs.moresynchro import RWLock
from sonicprobe.libs.http_json_server import HttpReqErrJson, HttpResponseJson

LOG = logging.getLogger('nsaproxy.modules.pdns')


def validate_params(params):
    if not isinstance(params, (list, dict)):
        return False
    elif len(params) == 0:
        return True

    return params

def validate_name(ip_addr):
    return network.valid_host(ip_addr, network.MASK_IPV4_DOTDEC | network.MASK_IPV6)


xys.add_callback('pdns.validate_params', validate_params)
xys.add_callback('pdns.validate_nameservers', network.valid_host)


class PDNSModule(DWhoModuleBase):
    MODULE_NAME     = 'pdns'

    LOCK            = RWLock()

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

    def _fetch_zone(self, request, params, path = None):
        res = self._do_request('get', path or request.get_path(), params, None, request.get_headers())
        if not res.text:
            return

        return res.json()

    def _check_api_key(self, request):
        api_key = request.headers.get('x-api-key') or self.api_key
        if not api_key:
            raise HttpReqErrJson("missing api key")
        request.headers['x-api-key'] = api_key

    def _do_request(self, method, path, params, payload, headers):
        uri    = list(self.api_uri)
        if path:
            uri[2] = path
        else:
            uri[2] = None

        h      = {}
        for k, v in headers.iteritems():
            if k.lower() != 'content-length':
                h[k.lower()] = v

        return getattr(requests, method.lower())(urisup.uri_help_unsplit(uri),
                                                 params  = params,
                                                 json    = payload,
                                                 headers = h)

    def _do_response(self, request, params = None, args = None):
        r =  self._do_request(request.get_method(), request.get_path(), params, args, request.get_headers())
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
        for api_sync in APIS_SYNC.itervalues():
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

        if not self.LOCK.acquire_read(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for reading after %s seconds" % self.lock_timeout)

        try:
            return self._do_response(request, params)
        except HttpReqErrJson, e:
            raise
        except Exception, e:
            LOG.exception("%r", e)
        finally:
            self.LOCK.release()


    ENDPOINT_PUT_QSCHEMA = xys.load("""
    server_id:    !!str
    endpoint:     !!str
    id:           !!str
    command*:     !~~enum(axfr-retrieve,notify,rectify)
    domain*:      !!str
    """)

    def api_endpoint_put(self, request):
        params = request.query_params()

        self._check_api_key(request)

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.ENDPOINT_PUT_QSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command")

        if not self.LOCK.acquire_read(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for reading after %s seconds" % self.lock_timeout)

        try:
            return self._do_response(request, params)
        except HttpReqErrJson, e:
            raise
        except Exception, e:
            LOG.exception("%r", e)
        finally:
            self.LOCK.release()


    ENDPOINT_POST_QSCHEMA = xys.load("""
    server_id?:   !!str
    endpoint?:    !!str
    """)

    ENDPOINT_POST_PSCHEMA = xys.load("""
    nameservers?:  [ !!str ]
    masters?:      [ !!str ]
    kind?:         !~~enum(native,master,slave)
    name?:         !!str
    soa_edit_api?: !~~enum(INCEPTION-INCREMENT,EPOCH,INCEPTION-EPOCH)
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

        if not self.LOCK.acquire_write(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for reading after %s seconds" % self.lock_timeout)

        try:
            uids        = []
            nameservers = []

            if params.get('endpoint') == 'zones':
                uids = self._push_apis_sync('create_hosted_zone', params, args)
            else:
                raise HttpReqErrJson(400, "invalid request")

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

            r = self._do_response(request, None, args)
            if not args.get('nameservers') or not r:
                return r

            data = r.get_data()
            if data:
                data = json.loads(data)
                if data and 'id' in data:
                    self._refresh_apis(data)

            return r
        except HttpReqErrJson, e:
            raise
        except Exception, e:
            LOG.exception("%r", e)
        finally:
            self.LOCK.release()


    ENDPOINT_PATCH_QSCHEMA = xys.load("""
    server_id:    !!str
    endpoint:     !!str
    id:           !!str
    """)

    ENDPOINT_PATCH_PSCHEMA = xys.load("""
    nameservers?:  [ !!str ]
    masters?:      [ !!str ]
    kind?:         !~~enum(native,master,slave)
    name?:         !!str
    soa_edit_api?: !~~enum(INCEPTION-INCREMENT,EPOCH,INCEPTION-EPOCH)
    rrsets?:       !~~seqlen(0,999)
      - records:
          - content*: !!str
            disabled: !~~isBool
            set-prt?: !~~isBool
        changetype:   !~~enum(DELETE,REPLACE)
        type:    !~~enum(A,AAAA,CAA,CNAME,RCNAME,MX,NS,PTR,SOA,SPF,SRV,TXT)
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

        if not self.LOCK.acquire_write(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for reading after %s seconds" % self.lock_timeout)

        try:
            uids = []

            if params.get('endpoint') == 'zones':
                if not args.get('rrsets'):
                    return self._do_response(request, None, args)

                zone = self._fetch_zone(request, params)
                uids = self._push_apis_sync('change_rrsets', params, args, zone)
            else:
                raise HttpReqErrJson(400, "invalid request")

            if not uids:
                raise HttpReqErrJson(500, "unable to retrieve uids")

            res = self._get_results(uids)
            if res['failed']:
                raise HttpReqErrJson(409, "failed to synchronize on dns provider. (errors: %r)" % res['failed'])

            return self._do_response(request, None, args)
        except HttpReqErrJson, e:
            raise
        except Exception, e:
            LOG.exception("%r", e)
        finally:
            self.LOCK.release()


    ENDPOINT_DELETE_QSCHEMA = xys.load("""
    server_id:   !!str
    endpoint:    !!str
    id:          !!str
    """)

    def api_endpoint_delete(self, request):
        params  = request.query_params()

        self._check_api_key(request)

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type for query parameters")

        if not xys.validate(params, self.ENDPOINT_DELETE_QSCHEMA):
            raise HttpReqErrJson(415, "invalid arguments for command for query parameters")

        if not self.LOCK.acquire_write(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for reading after %s seconds" % self.lock_timeout)

        try:
            uids = []

            if params.get('endpoint') == 'zones':
                uids = self._push_apis_sync('delete_hosted_zone', params)
            else:
                raise HttpReqErrJson(400, "invalid request")

            if not uids:
                raise HttpReqErrJson(500, "unable to retrieve uids")

            res = self._get_results(uids)
            if res['failed']:
                raise HttpReqErrJson(409, "failed to synchronize on dns provider. (errors: %r)" % res['failed'])

            return self._do_response(request)
        except HttpReqErrJson:
            raise
        except Exception, e:
            LOG.exception("%r", e)
        finally:
            self.LOCK.release()


if __name__ != "__main__":
    def _start():
        MODULES.register(PDNSModule())
    _start()
