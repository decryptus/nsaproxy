#!/bin/bash

NSAPROXY_ROOT="${NSAPROXY_ROOT:-"/etc/nsaproxy"}"
NSAPROXY_CONFFILE="${NSAPROXY_CONFFILE:-"${NSAPROXY_ROOT}/nsaproxy.yml"}"

mkdir -p "${NSAPROXY_ROOT}"

cd "${NSAPROXY_ROOT}"

if [[ ! -f "${NSAPROXY_CONFFILE}" ]] && [[ ! -z "${NSAPROXY_CONFIG}" ]];
then
    echo -e "${NSAPROXY_CONFIG}" > "${NSAPROXY_CONFFILE}"
fi

exec nsaproxy -f ${NSAPROXY_EXTRA_OPTS}
