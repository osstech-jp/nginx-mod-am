OpenAM Policy Agent for Nginx
=============================

# Supported Platforms

 - Red Hat Enterprise Linux 6.0
 - Scientific Linux 6
 - CentOS 6
 - Debian 7
 - Ubuntu 12

# Requirement library

You need to install folowing library due to the nginx agent linked the
library dynamical.

 - RHEL/CentOS
    # yum install nspr nss openssl

 - Debian/Ubuntu
    # apt-get install libnspr4 libnss3 libssl1.0.0

# Agent Installation

## Steps

 1. Extract nginx_Linux_64_agent_rXXXX.zip installation bits.

    # unzip nginx_Linux_64_agent_rXXXX.zip -d /opt

 2. Goto web_agents/nginx_agent

    # cd /opt/web_agents/nginx_agent/

 3. Execute agentadmin.sh

    # ./bin/agentadmin.sh

 4. Follow the installation interactions and provide these details:

 - OpenSSO server URL
 - Agent URL
 - Agent Profile name
 - Agent Password

 5. Execute nginx

    # ./bin/nginx

# Agent Uninstallation

stop nginx and delete web_agents/nginx_agent directory.

# Nginx Configuration

agentadmin.sh aready added following configuration:

    http {
        ...
        am_boot_file "/path/to/OpenSSOAgentBootstrap.properties";
        am_conf_file "/path/to/OpenSSOAgentConfiguration.properties";

If you want to use nginx as a reverce proxy.

    location / {
        ...
        proxy_pass        http://example.com:80/;
        proxy_set_header  X-Real-IP  $remote_addr;

Currently I recommend one worker process because multi process mode
does not work notification from OpenAM.

Pretty soon, I'll try solving the multi process problem. However Nginx
work very well with only one process.

    worker_processes  1;

If you found some problem, then please send me the debug logfile.

    error_log logs/error.log debug_http;
