# -*- coding: utf-8 -*-
"""nsaproxy apis"""

__author__  = "Adrien DELLE CAVE <adc@doowan.net>"
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

import abc
import logging
import Queue
import threading

from dwho.classes.plugins import DWhoPluginBase

LOG       = logging.getLogger('nsaproxy.apis')


class NSAProxyApisSync(dict):
    def register(self, api_sync):
        if not isinstance(api_sync, NSAProxyApiSync):
            raise TypeError("Invalid Api Sync class. (class: %r)" % api_sync)
        return dict.__setitem__(self, api_sync.name, api_sync)

APIS_SYNC = NSAProxyApisSync()


class NSAProxyApiObject(object):
    def __init__(self, name, uid, endpoint, zone, params, args, callback):
        self.name     = name
        self.uid      = uid
        self.endpoint = endpoint
        self.zone     = zone
        self.params   = params
        self.args     = args
        self.callback = callback
        self.result   = None
        self.errors   = []

    def get_uid(self):
        return self.uid

    def add_error(self, error):
        self.errors.append(error)
        return self

    def has_error(self):
        return len(self.errors) != 0

    def get_errors(self):
        return self.errors

    def set_result(self, result):
        self.result = result

        return self

    def get_result(self):
        return self.result

    def get_endpoint(self):
        return self.endpoint

    def get_zone(self):
        return self.zone

    def get_params(self):
        return self.params

    def get_args(self):
        return self.args

    def __call__(self):
        return self.callback(self)


class NSAProxyApiSync(dict):
    __metaclass__ = abc.ABCMeta

    def __init__(self, plugin_name):
        self.name       = plugin_name
        self.queue      = Queue.Queue()
        self.results    = {}

    def qput(self, item):
        return self.queue.put(item)

    def qget(self, block = True, timeout = None):
        return self.queue.get(block, timeout)


class NSAProxyApiBase(threading.Thread, DWhoPluginBase):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        threading.Thread.__init__(self)
        DWhoPluginBase.__init__(self)
        self.daemon = True
        self.name   = self.PLUGIN_NAME

    def _is_in_cache(self, rrcache, change):
        for record in rrcache:
            if cmp(record, change) == 0:
                return True

        return False

    def _has_excluded(self, zoneid):
        return 'exclude' in self.config['plugins'][self.PLUGIN_NAME] \
               and zoneid in self.config['plugins'][self.PLUGIN_NAME]['exclude']

    def _is_excluded_zone(self, zoneid):
        if not self._has_excluded(zoneid):
            return False

        return self.config['plugins'][self.PLUGIN_NAME]['exclude'][zoneid] == '*'

    def _is_excluded_record(self, zoneid, record_type, record_name):
        if not self._has_excluded(zoneid):
            return False

        ref_conf = self.config['plugins'][self.PLUGIN_NAME]['exclude'][zoneid]

        if not isinstance(ref_conf, dict):
            LOG.warning("exclude record must be a dict or '*': %r", ref_conf)
            return False

        if record_type not in ref_conf:
            return False

        if ref_conf[record_type] == '*':
            return True

        if not isinstance(ref_conf[record_type], list):
            LOG.warning("exclude record must be a list or '*': %r", ref_conf[record_type])
            return False

        return record_name in ref_conf[record_type]

    def _keyname_zone(self, zoneid):
        return "nsa.%s.zone:%s" % (self.PLUGIN_NAME, zoneid)

    def _keyname_rrsets(self, zoneid):
        return "nsa.%s.rrsets:%s" % (self.PLUGIN_NAME, zoneid)

    def run(self):
        while True:
            r = None

            try:
                obj  = APIS_SYNC[self.PLUGIN_NAME].qget(True)
                func = "_do_%s" % obj.get_endpoint()
                if not hasattr(self, func):
                    LOG.warning("unknown endpoint function: %r", func)
                    continue

                r    = getattr(self, func)(obj)
            except Exception, e:
                obj.add_error(str(e))
                LOG.exception("%r", e)
            else:
                obj.set_result(r)
            finally:
                obj()

    def __call__(self):
        self.start()
        return self
