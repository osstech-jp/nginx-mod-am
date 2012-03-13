OpenAM Policy Agent for Nginx
=============================

***THIS MODULE IN THE EXPERIMENTAL PHASE***

***JUST WAIT A LITTLE LONGER WHEN USING YOUR PRODUCTION ENVIROMENT***

# Platforms

Currently, This module will works Linux only. I'm testing Scientific
Linux 6 and Debian Wheezy.

# Build Instructions

 1. Build libamsdk

    libamsdk's build instructions is here:

    <OPENAM_DIR>/products/webagents/docs/Linux/apache/README.txt

    But we are not following the instructions. Our libamsdk is dynamic
    linked with libxml2, nss and nspr that is provided Linux
    distribution.

    Therefore, this module building may fail.
    We'll distribute our libamsdk binary if your request.

 2. Download nginx policy agent

    This is temporary repository:

        $ git clone https://bitbucket.org/hamano/nginx-mod-am.git

 3. Edit nginx-mod-am/config file

    Specify libamsdk location:

        AM_INC=<OPENAM_DIR>/products/webagents/built/include/
        AM_LIB=<OPENAM_DIR>/products/webagents/built/Linux/lib/

 4. Download stable nginx

    http://nginx.org/en/download.html

        $ wget http://nginx.org/download/nginx-1.0.13.tar.gz
        $ tar xzf nginx-1.0.13.tar.gz
        $ cd nginx-1.0.13
        $ ./configure --prefix=<NGINX_INSTALL_DIR> \
            --add-module=../nginx-mod-am --with-http_ssl_module
        $ make
        # make install

    Currently Nginx does not suppot DSO(dynamic loadable module) yet, But
    probably it will support at an early date.

# Configuration

Add the following line to http context in nginx.conf.
Property file is taken from another agent.

    http {
        ...
        am_boot_file "/path/to/OpenSSOAgentBootstrap.properties";
        am_conf_file "/path/to/OpenSSOAgentConfiguration.properties";

Currently I recommend one worker process because multi process mode
does not work notification from OpenAM.

Pretty soon, I'll try solving the multi process problem. However Nginx
work very well with only one process.

    worker_processes  1;

If you found some problem, then please send me the debug logfile.

    error_log  logs/error.log debug_http;

# TODO
 * POST data handling
 * notification handling with multi processes
