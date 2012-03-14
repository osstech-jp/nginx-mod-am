/*
 * Copyright (C) 2012 Tsukasa Hamano <hamano@osstech.co.jp>
 * Copyright (C) 2012 Open Source Solution Technology Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "am_web.h"

typedef struct{
    ngx_str_t boot_file;
    ngx_str_t conf_file;
}ngx_http_am_main_conf_t;

static ngx_int_t ngx_http_am_init(ngx_conf_t *cf);
static void *ngx_http_am_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_am_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_am_init_process(ngx_cycle_t *cycle);
static void ngx_http_am_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_am_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_am_commands[] = {
    { ngx_string("am_boot_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_am_main_conf_t, boot_file),
      NULL },
    { ngx_string("am_conf_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_am_main_conf_t, conf_file),
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_am_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_am_init,              /* postconfiguration */

    ngx_http_am_create_main_conf,  /* create main configuration */
    ngx_http_am_init_main_conf,    /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL,                          /* merge location configuration */
};

ngx_module_t ngx_http_am_module = {
    NGX_MODULE_V1,
    &ngx_http_am_module_ctx,       /* module context */
    ngx_http_am_commands,          /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_am_init_process,      /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    ngx_http_am_exit_process,      /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static am_status_t
ngx_http_am_set_user(void **args, const char *user)
{
    am_status_t st = AM_SUCCESS;
    ngx_http_request_t *r = args[0];
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "user=%s", user);
    return st;
}

static am_status_t
ngx_http_am_render_result(void **args, am_web_result_t result, char *data)
{
    am_status_t st = AM_SUCCESS;
    ngx_http_request_t *r = args[0];
    int *ret = args[1];
    ngx_table_elt_t *header;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "RESULT=%s(%d)",
                  am_web_result_num_to_str(result), result);

    switch(result){
    case AM_WEB_RESULT_OK:
        *ret = NGX_DECLINED;
        break;
    case AM_WEB_RESULT_OK_DONE:
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "openam responsed AM_WEB_RESULT_OK_DONE. "
                      "I don't know this case, please tell me how to reproduce"
            );
        *ret = NGX_DECLINED;
        break;
    case AM_WEB_RESULT_REDIRECT:
        if(!data){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "redirect data is null.");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        header = ngx_list_push(&r->headers_out.headers);
        if(!header){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "insufficient memory");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        header->hash = 1;
        ngx_str_set(&header->key, "Location");
        header->value.len = strlen(data);
        header->value.data = ngx_palloc(r->pool, header->value.len);
        ngx_memcpy(header->value.data, data, header->value.len);
        *ret = NGX_HTTP_MOVED_TEMPORARILY;
        break;
    case AM_WEB_RESULT_FORBIDDEN:
        *ret = NGX_HTTP_FORBIDDEN;
        break;
    case AM_WEB_RESULT_ERROR:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "AM_WEB_RESULT_ERROR");
        *ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
        break;
    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Unknown Error result=%s(%d)",
                      am_web_result_num_to_str(result), result);
        *ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
        break;
    }
    return st;
}

am_status_t
ngx_http_am_set_header_in_request(void **args,
                                  const char *key,
                                  const char *val)
{
    ngx_http_request_t *r = args[0];
    ngx_table_elt_t *header;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_am_set_header_in_request() "
                  "key=%s, val=%s", key, val?val:"(null)");
    if(!val){
        return AM_SUCCESS;
    }

    if(!strcasecmp(key, "cookie")){
        // ignore cookie header
        return AM_SUCCESS;
    }
    header = ngx_list_push(&r->headers_in.headers);
    if(!header){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return AM_FAILURE;
    }

    header->hash = 0;
    header->key.len = strlen(key);
    header->key.data = ngx_palloc(r->pool, header->key.len);
    if(!header->key.data){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return AM_FAILURE;
    }
    ngx_memcpy(header->key.data, key, header->key.len);

    header->value.len = strlen(val);
    header->value.data = ngx_palloc(r->pool, header->value.len);
    if(!header->value.data){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return AM_FAILURE;
    }
    ngx_memcpy(header->value.data, val, header->value.len);

    return AM_SUCCESS;
}

am_status_t
ngx_http_am_add_header_in_response(void **args,
                                   const char *key,
                                   const char *val)
{
    ngx_http_request_t *r = args[0];
    ngx_table_elt_t *header;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_am_add_header_in_response() "
                  "key=%s, val=%s", key, val);
    if(!val){
        return AM_SUCCESS;
    }
    header = ngx_list_push(&r->headers_out.headers);
    if(!header){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return AM_FAILURE;
    }

    header->hash = 1;
    header->key.len = strlen(key);
    header->key.data = ngx_palloc(r->pool, header->key.len);
    if(!header->key.data){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return AM_FAILURE;
    }
    ngx_memcpy(header->key.data, key, header->key.len);

    header->value.len = strlen(val);
    header->value.data = ngx_palloc(r->pool, header->value.len);
    if(!header->value.data){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return AM_FAILURE;
    }
    ngx_memcpy(header->value.data, val, header->value.len);

    return AM_SUCCESS;
}

/*
 * duplicate null-terminated string from pascal string.
 */
static char *ngx_pstrdup_nul(ngx_pool_t *pool, ngx_str_t *src)
{
    char *dst;
    dst = ngx_pnalloc(pool, src->len + 1);
    if(!dst){
        return NULL;
    }
    ngx_memcpy(dst, src->data, src->len);
    dst[src->len] = '\0';
    return dst;
}

/*
 * get cookie
 * TODO: use ngx_http_parse_multi_header_lines()
 */
static char* ngx_http_am_get_cookie(ngx_http_request_t *r){
    ngx_array_t *cookies = &r->headers_in.cookies;
    ngx_table_elt_t  **elts = cookies->elts;
    char *cookie = NULL;

    if(cookies->nelts == 1){
        cookie = ngx_pstrdup_nul(r->pool, &elts[0]->value);
    }else if(cookies->nelts > 1){
        unsigned int i;
        for(i = 0; i < cookies->nelts; i++){
            cookie = ngx_pstrdup_nul(r->pool, &elts[i]->value);
            // FIXME: merge multiple cookie
        }
    }
    return cookie;
}

/*
 * construct full url
 * NOTE: Shoud we use am_web_get_all_request_urls()
 * sjsws agent is using it but apache agent is not using
 */
static char* ngx_http_am_get_url(ngx_http_request_t *r){
    char *proto = NULL;
    char *host = NULL;
    char *path = NULL;
    char *url = NULL;
    size_t len = 4; // "://" + '\0'
    int is_ssl = 0;

#if (NGX_HTTP_SSL)
    /* detect SSL connection */
    if(r->connection->ssl){
        is_ssl = 1;
    }
#endif
    if(is_ssl){
        proto = "https";
        len += 5;
    }else{
        proto = "http";
        len += 4;
    }

    if(r->headers_in.host){
        if(!(host = ngx_pstrdup_nul(r->pool, &r->headers_in.host->value))){
            return NULL;
        }
        len += r->headers_in.host->value.len;
    }else{
        // using gethostname(2) when no host header.
        if(!(host = ngx_pstrdup_nul(r->pool,
                                    (ngx_str_t *)&ngx_cycle->hostname))){
            return NULL;
        }
        len += ngx_cycle->hostname.len;
    }

    // Should we chop query parameter from the uri?
    // see http://java.net/jira/browse/OPENSSO-5552
    len += r->unparsed_uri.len;
    if(!(path = ngx_pstrdup_nul(r->pool, &r->unparsed_uri))){
        return NULL;
    }
    if(!(url = ngx_pnalloc(r->pool, len))){
        return NULL;
    }
    // construct url PROTO://HOST:PORT/PATH
    // No need to append default port(80 or 443), may be...
    snprintf(url, len, "%s://%s%s", proto, host, path);
    return url;
}

static ngx_int_t
ngx_http_am_setup_request_parms(ngx_http_request_t *r,
                                am_web_request_params_t *parms){
    memset(parms, 0, sizeof(am_web_request_params_t));
    char *url = ngx_http_am_get_url(r);
    if(!url){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return NGX_ERROR;
    }

    char *query = ngx_pstrdup_nul(r->pool, &r->args);
    if(!query){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return NGX_ERROR;
    }

    char *method = ngx_pstrdup_nul(r->pool, &r->method_name);
    if(!method){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return NGX_ERROR;
    }
    char *addr = ngx_pstrdup_nul(r->pool, &r->connection->addr_text);
    if(!addr){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return NGX_ERROR;
    }
    char *cookie = ngx_http_am_get_cookie(r);

    parms->url = url;
    parms->query = query;
    parms->method = am_web_method_str_to_num(method);
    parms->path_info = NULL; // TODO: What is using the parameter for?
    parms->client_ip = addr;
    parms->cookie_header_val = cookie;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "Request Params: url=%s, query=%s, method=%s, "
                  "path_info=%s, client_ip=%s, cookie=%s",
                  parms->url, parms->query, method,
                  parms->path_info?parms->path_info:"(null)",
                  parms->client_ip,
                  parms->cookie_header_val?parms->cookie_header_val:"(null)");
    return NGX_OK;
}

static ngx_int_t
ngx_http_am_setup_request_func(ngx_http_request_t *r,
                               am_web_request_func_t *func,
                               void **args
    ){
    memset((void *)func, 0, sizeof(am_web_request_func_t));
    func->set_user.func = ngx_http_am_set_user;
    func->set_user.args = args;
    func->render_result.func = ngx_http_am_render_result;
    func->render_result.args = args;
    func->set_header_in_request.func = ngx_http_am_set_header_in_request;
    func->set_header_in_request.args = args;
    func->add_header_in_response.func = ngx_http_am_add_header_in_response;
    func->add_header_in_response.args = args;
    return NGX_OK;
}

static ngx_int_t
ngx_http_am_init(ngx_conf_t *cf)
{
    ngx_log_error(NGX_LOG_DEBUG, cf->log, 0, "ngx_http_am_init()");
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_am_handler;
    return NGX_OK;
}

static void *
ngx_http_am_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_am_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_am_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    return conf;
}

static char *
ngx_http_am_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_am_main_conf_t *amcf = conf;

    if(amcf->boot_file.len == 0){
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                      "insufficiency configration. "
                      "please set am_boot_file.");
        return NGX_CONF_ERROR;
    }

    if(amcf->conf_file.len == 0){
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                      "insufficiency configration. "
                      "please set am_conf_file.");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_am_init_process(ngx_cycle_t *cycle)
{
    ngx_http_am_main_conf_t *conf;
    am_status_t status;
    boolean_t initialized = B_FALSE;

    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0,
                  "ngx_http_am_init_process()");

    conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_am_module);

    // TODO: is this safe?(null-terminated?)
    status = am_web_init((char *)conf->boot_file.data,
                         (char *)conf->conf_file.data);
    if(status != AM_SUCCESS){
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "am_web_init error status=%s(%d)",
                      am_status_to_name(status), status);
        return NGX_ERROR;
    }

    // No need to synchronize due to nginx is single thread model.
    status = am_agent_init(&initialized);
    if(status != AM_SUCCESS){
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "am_agent_init error status=%s(%d)",
                      am_status_to_name(status), status);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_http_am_exit_process(ngx_cycle_t *cycle)
{
    am_cleanup();
}

/*
 * calculate chain buffer size.
 */
static size_t ngx_chain_size(ngx_chain_t *chain){
    size_t size = 0;
    while(chain && chain->buf){
        size += ngx_buf_size(chain->buf);
        chain = chain->next;
    }
    return size;
}

/*
 * concatnate chain buffer.
 */
static char *ngx_chain_cat(ngx_http_request_t *r, ngx_chain_t *chain){
    size_t size = ngx_chain_size(chain);
    char *buf = ngx_palloc(r->pool, size + 1);
    if(!buf){
        return NULL;
    }
    char *p = buf;
    while(chain && chain->buf){
        ngx_memcpy(p,
                   chain->buf->pos,
                   ngx_buf_size(chain->buf));
        p = p + ngx_buf_size(chain->buf);
        chain = chain->next;
    }
    buf[size] = '\0';
    return buf;
}

static void
ngx_http_am_read_body(ngx_http_request_t *r)
{
}

static ngx_int_t
ngx_http_am_notification_handler(ngx_http_request_t *r, void *agent_config)
{
    ngx_int_t ret;
    static ngx_str_t type = ngx_string("text/plain");
    static ngx_str_t value = ngx_string("OK\n");
    ngx_http_complex_value_t cv;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "notification request.");

    ret = ngx_http_read_client_request_body(r, ngx_http_am_read_body);
    if(!r->request_body || !r->request_body->bufs){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no request body.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // concatnate chain buffer.
    char *body = ngx_chain_cat(r, r->request_body->bufs);
    if(!body){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    am_web_handle_notification(body,
                               strlen(body),
                               agent_config);
    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));
    cv.value = value;
    ngx_http_send_response(r, NGX_HTTP_OK, &type, &cv);
    return NGX_HTTP_OK;
}

static ngx_int_t
ngx_http_am_handler(ngx_http_request_t *r)
{
    am_status_t status;
    int ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
    am_web_result_t result;
    am_web_request_params_t req_params;
    am_web_request_func_t req_func;
    void *args[2] = {r, &ret};
    void *agent_config = NULL;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_am_handler()");

    /* we response to 'GET' and 'HEAD' and 'POST' requests only */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if(ngx_http_am_setup_request_parms(r, &req_params) != NGX_OK){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error at ngx_http_am_setup_request_parms()");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    agent_config = am_web_get_agent_configuration();
    if(!agent_config){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error at am_web_get_agent_configuration()");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if(am_web_is_notification(req_params.url, agent_config) == B_TRUE){
        // Hmmm, How I notify to all process when working multiprocess mode.
        ret = ngx_http_am_notification_handler(r, agent_config);
        am_web_delete_agent_configuration(agent_config);
        return ret;
    }

    if(ngx_http_am_setup_request_func(r, &req_func, args) != NGX_OK){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error at ngx_http_am_setup_request_func()");
        am_web_delete_agent_configuration(agent_config);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result = am_web_process_request(
        &req_params, &req_func, &status, agent_config);
    if(status != AM_SUCCESS){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "am_web_process_request error. "
                      "status=%s(%d)", am_status_to_name(status), status);
        am_web_delete_agent_configuration(agent_config);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    am_web_delete_agent_configuration(agent_config);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "return code=%d", ret);
    return ret;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
