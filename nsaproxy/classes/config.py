# -*- coding: utf-8 -*-
# Copyright (C) 2018-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""nsaproxy.classes.config"""

import logging
import os
import signal

from six import iterkeys, viewitems
try:
    from six.moves import cStringIO as StringIO
except ImportError:
    from six import StringIO

from dwho.config import import_conf_files, init_modules, init_plugins, parse_conf, stop
from httpdis.httpdis import get_default_options
from mako.template import Template
from sonicprobe.helpers import load_yaml

_TPL_IMPORTS = ('from os import environ as ENV',
                'from sonicprobe.helpers import to_yaml as my')

LOG = logging.getLogger('nsaproxy.classes.config')


def import_file(filepath, config_dir = None, xvars = None):
    if not xvars:
        xvars = {}

    if config_dir and not filepath.startswith(os.path.sep):
        filepath = os.path.join(config_dir, filepath)

    with open(filepath, 'r') as f:
        return load_yaml(Template(f.read(),
                                  imports = _TPL_IMPORTS).render(**xvars))

def load_conf(xfile, options = None, envvar = None):
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    conf = {'_config_directory': None}

    if os.path.exists(xfile):
        with open(xfile, 'r') as f:
            conf = parse_conf(load_yaml(f))

        conf['_config_directory'] = os.path.dirname(os.path.abspath(xfile))
    elif envvar and os.environ.get(envvar):
        c = StringIO(os.environ[envvar])
        conf = parse_conf(load_yaml(c.getvalue()))
        c.close()
        conf['_config_directory'] = None

    for x in ('modules', 'plugins'):
        conf = import_conf_files(x, conf)

    init_modules(conf)
    init_plugins(conf)

    if not conf.get('dns'):
        conf['dns'] = {}

    if conf['dns'] and conf['dns'].get('domains'):
        for name, domain_cfg in viewitems(conf['dns']['domains']):
            cfg = {'rrsets': [],
                   'vars':   {}}

            for x in ('vars', 'rrsets'):
                if isinstance(cfg[x], list):
                    append_func = getattr(cfg[x], 'extend')
                else:
                    append_func = getattr(cfg[x], 'update')

                if domain_cfg.get("import_%s" % x):
                    append_func(import_file(domain_cfg["import_%s" % x],
                                            conf['_config_directory'],
                                            cfg))

                if x in domain_cfg:
                    append_func(domain_cfg[x])

            if not cfg['rrsets']:
                cfg = None

            if cfg:
                conf['dns']['domains'][name] = cfg

    if not options or not isinstance(options, object):
        return conf

    for def_option in iterkeys(get_default_options()):
        if getattr(options, def_option, None) is None \
           and def_option in conf['general']:
            setattr(options, def_option, conf['general'][def_option])

    setattr(options, 'configuration', conf)

    return options
