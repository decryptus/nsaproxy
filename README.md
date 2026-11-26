# nsaproxy project

Full documentation: <https://nsaproxy.readthedocs.io/>

## Quickstart

Using nsaproxy in Docker

`docker compose up -d`

See [docker-compose.yml](docker-compose.yml)

## Installation

```sh
pip install nsaproxy
```

## Running

### Running daemon

`nsaproxy -c <conffile> -p <pidfile> --logfile <logfile>`

### Running foreground

`nsaproxy -f -c <conffile> -p <pidfile> --logfile <logfile>`

See [configuration validation](docs/configuration-validation.md) for YAML schema
coverage and compatibility.
