#!/bin/sh

# Install script for nginx policy agent
#
# This script is just generating property files.
#
# Copyright (C) 2012 Tsukasa Hamano <hamano@osstech.co.jp>

#set -x

AGENT_ADMIN=`dirname "$0"`
AGENT_HOME=`readlink -f ${AGENT_ADMIN}/..`
CRYPT_UTIL="${AGENT_HOME}/bin/crypt_util"

AGENT_CONF_DIR=${AGENT_HOME}/conf
AGENT_BOOTSTRAP=${AGENT_CONF_DIR}/OpenSSOAgentBootstrap.properties
AGENT_CONFIG=${AGENT_CONF_DIR}/OpenSSOAgentConfiguration.properties
AGENT_BOOTSTRAP_TEMPL=${AGENT_CONF_DIR}/OpenSSOAgentBootstrap.template
AGENT_CONFIG_TEMPL=${AGENT_CONF_DIR}/OpenSSOAgentConfiguration.template

#RANDOM_SOURCE=/dev/random
# for debugging
RANDOM_SOURCE=/dev/urandom

usage(){
    cat << EOF

usage: $0 <option> [<arguments>]

The available options are:
--install: Installs a new Agent instance.

EOF
}

generate_key(){
    # EL6 have /usr/bin/base64 in coreutils
    # But the script need to working on other platform.
    head -c 24 ${RANDOM_SOURCE} | base64
}

agent_install_input(){
    cat << EOF
************************************************************************
Welcome to the OpenSSO Policy Agent for NGINX
************************************************************************

EOF

    echo 'Enter the URL where the OpenAM server is running.'
    echo 'Please include the deployment URI also as shown below:'
    echo '(http://opensso.sample.com:58080/opensso)'
    while [ -z ${OPENAM_URL} ]; do
        read -p "OpenSSO server URL: " OPENAM_URL
    done

    echo 'Enter the Agent profile name'
    while [ -z ${AGENT_PROFILE_NAME} ]; do
        read -p "Agent Profile Name: " AGENT_PROFILE_NAME
    done

    echo 'Enter the password to be used for identifying the Agent.'
    echo '*THIS IS NOT PASSWORD FILE*'
    stty -echo
    while [ -z ${AGENT_PASSWORD} ]; do
        read -p "Agent Password: " AGENT_PASSWORD
        echo
    done
    stty echo

    cat << EOF
-----------------------------------------------
SUMMARY OF YOUR RESPONSES
-----------------------------------------------
OpenSSO server URL : ${OPENAM_URL}
Agent Profile name : ${AGENT_PROFILE_NAME}
EOF
    echo 'Continue with Installation?'
    while [ -z ${CONFIRM} ]; do
        read -p "[y/N]: " CONFIRM
    done
    if [ ${CONFIRM} != "y" ]; then
        exit
    fi
}

agent_install(){
    AGENT_ENCRYPT_KEY=`generate_key`
    AGENT_ENCRYPTED_PASSWORD=`${CRYPT_UTIL} ${AGENT_PASSWORD} ${AGENT_ENCRYPT_KEY}`
    AGENT_LOGS_DIR="${AGENT_HOME}/logs/"
    sed -e "s%@OPENAM_URL@%${OPENAM_URL}%" \
        -e "s%@AGENT_PROFILE_NAME@%${AGENT_PROFILE_NAME}%" \
        -e "s%@AGENT_ENCRYPTED_PASSWORD@%${AGENT_ENCRYPTED_PASSWORD}%" \
        -e "s%@AGENT_ENCRYPT_KEY@%${AGENT_ENCRYPT_KEY}%" \
        -e "s%@AGENT_LOGS_DIR@%${AGENT_LOGS_DIR}%" \
        ${AGENT_BOOTSTRAP_TEMPL} > ${AGENT_BOOTSTRAP}

}

agent_install_input
agent_install

