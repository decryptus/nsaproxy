"""Configuration contracts use XYS without coercing values or initializing services."""
import copy
import unittest
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from nsaproxy.classes.configuration_schema import validate_configuration, DWhoConfigurationError


class ConfigurationSchemaTests(unittest.TestCase):
    def test_extensions_and_values_are_preserved_without_mutation(self):
        conf = {'general': {}, 'dns': {'domains': {'example.test.': {'vars': {}, 'rrsets': [], 'extension': 'PRIVATE'}}}, 'extension': {'data': [1]}}
        original = copy.deepcopy(conf)
        self.assertIs(validate_configuration(conf), conf)
        self.assertEqual(conf, original)

    def test_invalid_known_fields_cannot_hide_behind_extensions(self):
        cases = [None,
                 {'general': {}, 'dns': []},
                 {'general': {}, 'dns': {'domains': []}},
                 {'general': {}, 'dns': {'domains': {'example.test.': {'rrsets': {}}}}},
                 {'general': {}, 'dns': {'domains': {'example.test.': {'vars': []}}}}]
        for conf in cases:
            with self.assertRaises(DWhoConfigurationError) as caught:
                validate_configuration(conf)
            self.assertNotIn('PRIVATE', str(caught.exception))

    def test_invalid_values_are_not_in_validation_logs(self):
        with patch('nsaproxy.classes.configuration_schema.xys.LOG') as logger:
            with self.assertRaises(DWhoConfigurationError) as caught:
                validate_configuration({'general': 'PRIVATE-CONFIGURATION-VALUE'})
        self.assertNotIn('PRIVATE-CONFIGURATION-VALUE', str(caught.exception))
        self.assertNotIn('PRIVATE-CONFIGURATION-VALUE', str(logger.mock_calls))

    def test_invalid_file_precedes_module_initialization(self):
        import os
        import tempfile
        from nsaproxy.classes import config
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write('general: [PRIVATE]')
            with patch.object(config.signal, 'signal'), patch.object(config, 'init_modules') as init:
                with self.assertRaises(DWhoConfigurationError):
                    config.load_conf(path)
                init.assert_not_called()
        finally:
            os.unlink(path)

    def test_imported_component_types_and_opaque_values(self):
        from nsaproxy.classes.configuration_schema import validate_component
        for kind in ('rrsets',):
            value = [{'opaque': {'secret': 'PRIVATE'}}]
            self.assertIs(validate_component(value, kind), value)
            with self.assertRaises(DWhoConfigurationError):
                validate_component({'PRIVATE': 1}, kind)
        self.assertEqual(validate_component({'x': [1, 2]}, 'vars'), {'x': [1, 2]})
        with self.assertRaises(DWhoConfigurationError):
            validate_component([], 'vars')

    def test_yaml_file_and_environment_preserve_imports_and_inline_precedence(self):
        import os
        import tempfile
        import shutil
        from nsaproxy.classes import config
        directory = tempfile.mkdtemp()
        try:
            variables = os.path.join(directory, 'vars.yml')
            records = os.path.join(directory, 'rrsets.yml')
            source = os.path.join(directory, 'main.yml')
            with open(variables, 'w') as stream:
                stream.write('ttl: 30')
            with open(records, 'w') as stream:
                stream.write('- {ttl: ${vars["ttl"]}, name: example.test.}')
            content = ('general: {server_id: localhost}\ndns:\n  domains:\n    example.test.:\n'
                       '      import_vars: %s\n      vars: {ttl: 60}\n'
                       '      import_rrsets: %s\n      rrsets: [{ttl: 90}]\n') % (variables, records)
            with open(source, 'w') as stream:
                stream.write(content)
            with patch.object(config.signal, 'signal'), patch.object(config, 'init_modules'), \
                 patch.object(config, 'init_plugins'), patch.dict(os.environ, {'NSAPROXY_XYS_TEST': content}):
                for path in (source, source + '.missing'):
                    result = config.load_conf(path, envvar='NSAPROXY_XYS_TEST')
                    domain = result['dns']['domains']['example.test.']
                    self.assertEqual(domain['vars'], {'ttl': 60})
                    self.assertEqual(domain['rrsets'], [{'ttl': 60, 'name': 'example.test.'}, {'ttl': 90}])
        finally:
            shutil.rmtree(directory)
