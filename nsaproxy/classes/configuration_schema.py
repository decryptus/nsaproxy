"""XYS configuration structure checks, without loading or initializing services."""
from sonicprobe.libs import xys
from dwho.classes.errors import DWhoConfigurationError


xys.add_callback('nsaproxy.config.mapping', lambda value: isinstance(value, dict))
MAPPING = '!~~callback(nsaproxy.config.mapping) null'
MAPPING_SCHEMA = xys.load(MAPPING)


def validate_fields(data, schema):
    # Unknown fields belong to extensions. Never use a wildcard that could consume
    # known optional fields before their XYS validators run.
    if not isinstance(data, dict) or not xys.validate(
            {key: value for key, value in data.items() if key in schema}, schema):
        raise DWhoConfigurationError('Invalid configuration structure')
    return data



CONFIG_SCHEMA = xys.load('''
general: %s
dns*: %s
modules*: %s
plugins*: %s
''' % (MAPPING, MAPPING, MAPPING, MAPPING))
DNS_SCHEMA = xys.load('domains*: %s' % MAPPING)
DOMAIN_SCHEMA = xys.load('''
vars?: %s
rrsets?: [ !!any ]
import_vars*: !!str
import_rrsets*: !!str
''' % MAPPING)
COMPONENT_SCHEMAS = {'vars': MAPPING_SCHEMA, 'rrsets': xys.load('[ !!any ]')}


def validate_configuration(conf):
    validate_fields(conf, CONFIG_SCHEMA)
    dns = conf.get('dns') or {}
    validate_fields(dns, DNS_SCHEMA)
    for definition in (dns.get('domains') or {}).values():
        validate_fields(definition, DOMAIN_SCHEMA)
    return conf


def validate_component(data, kind):
    if not xys.validate(data, COMPONENT_SCHEMAS[kind]):
        raise DWhoConfigurationError('Invalid imported DNS component')
    return data
