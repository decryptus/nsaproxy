# Configuration validation

The file and environment loaders validate the general, DNS, domain, modules and
plugins section shapes. Domain vars are mappings, rrsets are lists and component
import paths are strings (or null when unused). Imported vars and rrsets are
validated after Mako rendering. Imports are still resolved relative to the main
file; inline vars override imported vars and inline rrsets append to imported
records. Provider options and DNS record semantics stay with their adapters.

XYS (Sonicprobe >= 0.3.57) validates parsed Python data; it does not replace the
YAML loader, resolve imports, initialize services or grant permissions. Schemas
are compiled once. These schemas use no modifiers and do not silently convert
values. The existing numeric normalization and semantic checks still apply.

Known application fields are validated explicitly. Extension settings remain
available where the existing contract permits them; this is not universal typo
detection for plugin configuration. Malformed section/component shapes now fail
with a configuration error instead of incidental attribute/update exceptions.
New validation errors do not include configuration values or credential contents.

`tests/test_configuration_schema.py` covers valid/invalid shapes and compatibility
at the loader boundary. Run the collection guard before the unittest suite:

```sh
python .github/scripts/check-test-collection.py --runner unittest tests
python -m unittest discover -s tests -v
```

These tests use synthetic data and mocked adapters or loopback services. They do
not establish provider availability or production acceptance.
