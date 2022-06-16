#!/bin/bash

# Usage: execute.sh [WildFly mode] [configuration file]
#
# The default mode is 'standalone' and default configuration is based on the
# mode. It can be 'standalone.xml' or 'domain.xml'.

echo "=> Executing Customization script"

PROJECT=${1}
ENV=${2}
GIT_DOMAIN_GROUP=${3}
GIT_ACCESS_TOKEN=${4}

UAFFRONTEND_CONFIG_PATH=/var/config/uaf
UAFFRONTEND_CERT_PATH=/var/cert/uaf

TMP_GIT=/tmp/${PROJECT}

function git_config() {
  echo "=> Start git configuration files"

  git clone -b master "https://oauth2:${GIT_ACCESS_TOKEN}@${GIT_DOMAIN_GROUP}/${PROJECT}.git" "${TMP_GIT}"
  cp -p "${TMP_GIT}/${ENV}/config/appsettings.json" "${UAFFRONTEND_CONFIG_PATH}"
  cp -p "${TMP_GIT}/${ENV}/cert/AuthServerCertificate.pfx" "${UAFFRONTEND_CERT_PATH}"

  echo "=> Finish git configuration files"
}

function start_uaf_frontend() {

  echo "=> Starting RUN UAF Frontend"
  
  dotnet /app/UAF_Frontend_Registration.dll
  
  echo "=> RUN UAF Frontend SUCCESS"
}

# Main
git_config
start_uaf_frontend
# End Main

