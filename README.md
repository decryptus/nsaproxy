# nsaproxy project

## Quickstart

Using nsaproxy in Docker

`docker-compose up -d`

See [docker-compose.yml](docker-compose.yml)

## Installation

pip install nsaproxy

## Running

### Running daemon

`nsaproxy -c <conffile> -p <pidfile> --logfile <logfile>`

### Running foreground

`nsaproxy -f -c <conffile> -p <pidfile> --logfile <logfile>`
