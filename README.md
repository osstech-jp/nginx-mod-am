OpenAM Policy Agent for Nginx
=============================

# Supported Platforms

 - Red Hat Enterprise Linux 6/7
 - CentOS 6/7
 - Debian 7
 - Ubuntu 12

# Requirement library

You need to install folowing library due to the nginx agent linked the
library dynamical.

 * RHEL/CentOS

~~~
# yum install nspr nss libxml2 pcpre openssl
~~~

 * Debian/Ubuntu

~~~
# apt-get install libnspr4 libnss3 libxml2 libpcre3 libssl1.0.0
~~~

# Agent Installation

## Steps

 1. Extract nginx_Linux_64_agent_rXXXX.zip installation bits.

 ~~~
 # unzip nginx_Linux_64_agent_rXXXX.zip -d /opt
 ~~~

 2. Goto web_agents/nginx_agent

 ~~~
 # cd /opt/web_agents/nginx_agent/
 ~~~

 3. Execute agentadmin.sh

 ~~~
 # ./bin/agentadmin.sh
 ~~~

 4. Follow the installation interactions and provide these details:

  - OpenSSO server URL
  - Agent URL
  - Agent Profile name
  - Agent Password

 5. Execute nginx
 ~~~
 # ./bin/nginx
 ~~~

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


# Build Instructions

1. Install Dependencies

 for RHEL or CentOS:

 ~~~
 # yum install zlib-devel nspr-devel nss-devel libxml2-devel pcre-devel openssl-dev
 ~~~

 for Debian:

 ~~~
 # apt-get install zlib1g-dev libnspr4-dev libnss3-dev libxml2-dev libpcre3-dev libssl-dev
 ~~~

2. Setup extlib

 You can download Agent SDK here:
 https://forgerock.org/downloads/openam-builds/

 ~~~
 $ unzip -d extlib common_3_0_Linux_64bit.zip
 $ ln -s libamsdk.so.3 extlib/lib/libamsdk.so
 ~~~

3. Build

 ~~~
 $ make dist
 ~~~
