/*
 * OpenAM Policy Agent for NGINX
 *
 * Copyright (C) 2012-2014 Open Source Solution Technology Corporation
 *
 * Authors:
 *  HAMANO Tsukasa <hamano@osstech.co.jp>
 *  Sergio Castaño Arteaga <sergio.castano.arteaga@gmail.com>
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

typedef struct {
    unsigned waiting_more_body:1;
} ngx_http_am_ctx_t;

void *agent_config = NULL;
boolean_t agent_initialized = B_FALSE;

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
ngx_http_am_read_body_handler(ngx_http_request_t *r){
    ngx_http_am_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_am_module);
    if (ctx->waiting_more_body) {
        ngx_http_core_run_phases(r);
    } else {
        ngx_http_finalize_request(r, NGX_DONE);
    }
}

static am_status_t
ngx_http_am_get_post_data(void **args, char **rbuf){
    ngx_http_request_t *r = args[0];
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_am_get_post_data()");
    *rbuf = ngx_chain_cat(r, r->request_body->bufs);
    if(!*rbuf){
        return AM_FAILURE;
    }
/*
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "body: %s\n", *rbuf);
*/
    return AM_SUCCESS;
}

static am_status_t
ngx_http_am_set_user(void **args, const char *user)
{
    am_status_t st = AM_SUCCESS;
    ngx_http_request_t *r = args[0];
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "set_user: %s", user);

    r->headers_in.user.len = strlen(user);
    r->headers_in.user.data = ngx_palloc(r->pool, r->headers_in.user.len);
    ngx_memcpy(r->headers_in.user.data, user, r->headers_in.user.len);
    return st;
}

static am_status_t
ngx_http_am_set_method(void **args, am_web_req_method_t method){
    ngx_http_request_t *r = args[0];
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "set_method: %d", method);
    switch(method){
    case AM_WEB_REQUEST_GET:
        r->method = NGX_HTTP_GET;
        break;
    case AM_WEB_REQUEST_POST:
        r->method = NGX_HTTP_POST;
        break;
    default:
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "set_method(%s) is not implement yet.",
                      am_web_method_num_to_str(method));
        return AM_INVALID_ARGUMENT;
    }
    return AM_SUCCESS;
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
        if(!data){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ok_done data is null.");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        header = ngx_list_push(&r->headers_out.headers);
        if(!header){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "insufficient memory");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_buf_t buf;
        ngx_chain_t out;
        out.buf = &buf;
        out.next = NULL;
        buf.pos = (u_char*)data;
        buf.last = (u_char*)data + strlen(data);
        buf.memory = 1;
        buf.last_buf = 1;
        r->headers_out.content_length_n = strlen(data);
        r->headers_out.content_type.data = (u_char *)"text/html";
        r->headers_out.content_type.len = 9;
        r->headers_out.status = NGX_HTTP_OK;

        ngx_http_send_header(r);

        if(ngx_http_output_filter(r, &out)){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "error at ngx_http_output_filter()");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        *ret = NGX_HTTP_OK;
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

/*
 * lookup header slow version
 * TODO: quick search does not working
 * see http://wiki.nginx.org/HeadersManagement
 */
ngx_table_elt_t *ngx_http_am_lookup_header(ngx_http_request_t *r,
                                           u_char *key)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i;
    size_t len = strlen((char *)key);

    part = &r->headers_in.headers.part;
    h = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (len != h[i].key.len || ngx_strcasecmp(key, h[i].key.data) != 0) {
            continue;
        }
        return &h[i];
    }
    return NULL;
}

/*
 * delete header utility
 * The crazy utility was written because nginx have no unsetting
 * header function like a apr_table_unset().
 * This will replace when correct way is available.
 */
ngx_int_t
ngx_http_am_delete_header_part(ngx_list_t *l,
                               ngx_list_part_t *cur,
                               ngx_uint_t i)
{
    ngx_table_elt_t *elts = cur->elts;
    ngx_list_part_t *new, *part;

    if (i == 0) {
        cur->elts = (char *) cur->elts + l->size;
        cur->nelts--;

        if (cur == l->last) {
            if (l->nalloc > 1) {
                l->nalloc--;
                return NGX_OK;
            }
            part = &l->part;
            while (part->next != cur) {
                if (part->next == NULL) {
                    return NGX_ERROR;
                }
                part = part->next;
            }
            part->next = NULL;
            l->last = part;
            return NGX_OK;
        }

        if (cur->nelts == 0) {
            part = &l->part;
            while (part->next != cur) {
                if (part->next == NULL) {
                    return NGX_ERROR;
                }
                part = part->next;
            }

            part->next = cur->next;
            return NGX_OK;
        }
        return NGX_OK;
    }

    if (i == cur->nelts - 1) {
        cur->nelts--;
        if (cur == l->last) {
            l->nalloc--;
        }
        return NGX_OK;
    }

    new = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
    if (new == NULL) {
        return NGX_ERROR;
    }

    new->elts = &elts[i + 1];
    new->nelts = cur->nelts - i - 1;
    new->next = cur->next;

    l->nalloc = new->nelts;

    cur->nelts = i;
    cur->next = new;
    if (cur == l->last) {
        l->last = new;
    }

    cur = new;
    return NGX_OK;
}

/*
 * delete header if exists
 */
void ngx_http_am_delete_header(ngx_http_request_t *r,
                               u_char *key)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i;
    size_t len = strlen((char *)key);

    part = &r->headers_in.headers.part;
    h = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (len == h[i].key.len && ngx_strcasecmp(key, h[i].key.data) == 0) {
            /* This is incompletion. */
            /*
              h[i].hash = 0;
              h[i].key.len = 0;
              h[i].key.data = NULL;
              h[i].value.len = 0;
              h[i].value.data = NULL;
            */
            ngx_http_am_delete_header_part(&r->headers_in.headers, part, i);
        }
    }
}

static am_status_t
ngx_http_am_set_header_in_request(void **args,
                                  const char *key,
                                  const char *val)
{
    ngx_http_request_t *r = args[0];
    ngx_table_elt_t *header = NULL;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_am_set_header_in_request() "
                  "key=%s, val=%s", key, val?val:"(null)");

    // delete header if val is NULL
    if(!val){
        ngx_http_am_delete_header(r, (u_char *)key);
        return AM_SUCCESS;
    }

    // overwrite header if key exist
    header = ngx_http_am_lookup_header(r, (u_char *)key);
    if(!header){
        // add header
        header = ngx_list_push(&r->headers_in.headers);
    }
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

static am_status_t
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
static am_status_t
ngx_http_am_check_postdata(void **args,
                           const char *requestURL,
                           char **page,
                           const unsigned long postcacheentry_life) {
    ngx_http_request_t *r = args[0];
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_am_check_postdata() "
                  "requestURL=%s", requestURL);
    return AM_SUCCESS;
}
*/

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
    int i;

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

    /*
     * trailing slashs.
     * see https://bugster.forgerock.org/jira/browse/OPENAM-2969
     */
    for(i = r->unparsed_uri.len - 1; i >= 0; i--){
        if(path[i] == '/'){
            path[i] = '\0';
        }else{
            break;
        }
    }

    if(!(url = ngx_pnalloc(r->pool, len))){
        return NULL;
    }
    /*
     * construct url PROTO://HOST:PORT/PATH
     * No need to append default port(80 or 443), may be...
     */
    snprintf(url, len, "%s://%s%s", proto, host, path);
    return url;
}

static ngx_int_t
ngx_http_am_setup_request_parms(ngx_http_request_t *r,
                                am_web_request_params_t *parms){
    memset(parms, 0, sizeof(am_web_request_params_t));
    parms->url = ngx_http_am_get_url(r);
    if(!parms->url){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return NGX_ERROR;
    }

    parms->query = ngx_pstrdup_nul(r->pool, &r->args);
    if(!parms->query){
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

    parms->method = am_web_method_str_to_num(method);
    if(parms->method == AM_WEB_REQUEST_UNKNOWN){
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "unknown request method: %s", method);
        return NGX_HTTP_NOT_ALLOWED;
    }

    /*
     * parms->path_info should be empty string in the same behavior as
     * apache22 agent.
     */
    parms->path_info = "";

    parms->client_ip = ngx_pstrdup_nul(r->pool, &r->connection->addr_text);
    if(!parms->client_ip){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        return NGX_ERROR;
    }

    parms->cookie_header_val = ngx_http_am_get_cookie(r);

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

    func->get_post_data.func = ngx_http_am_get_post_data;
    func->get_post_data.args = args;
    func->set_user.func = ngx_http_am_set_user;
    func->set_user.args = args;
    func->set_method.func = ngx_http_am_set_method;
    func->set_method.args = args;

    func->render_result.func = ngx_http_am_render_result;
    func->render_result.args = args;
    func->set_header_in_request.func = ngx_http_am_set_header_in_request;
    func->set_header_in_request.args = args;
    func->add_header_in_response.func = ngx_http_am_add_header_in_response;
    func->add_header_in_response.args = args;

/* not implement yet
    func->check_postdata.func = ngx_http_am_check_postdata;
    func->check_postdata.args = args;
*/
    return NGX_OK;
}

static ngx_int_t
ngx_http_am_init(ngx_conf_t *cf)
{
    ngx_log_error(NGX_LOG_DEBUG, cf->log, 0, "ngx_http_am_init()");
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;

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
    char *agent_version[4];

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "ngx_http_am_init_process()");
    conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_am_module);

    am_agent_version(agent_version);
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "version: %s, date: %s", agent_version[0], agent_version[2]);

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
    status = am_agent_init(&agent_initialized);
    if(status != AM_SUCCESS){
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "am_agent_init error status=%s(%d)",
                      am_status_to_name(status), status);
        // retry init at requesting time
    }

    agent_config = am_web_get_agent_configuration();
    if(!agent_config){
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "error at am_web_get_agent_configuration()");
        // retry at requesting time
    }

    return NGX_OK;
}

static void
ngx_http_am_exit_process(ngx_cycle_t *cycle)
{
    am_web_cleanup();
}

static ngx_int_t
ngx_http_am_notification_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "notification request.");

    static ngx_str_t type = ngx_string("text/plain");
    static ngx_str_t value = ngx_string("OK\n");
    ngx_http_complex_value_t cv;

    if(!r->request_body || !r->request_body->bufs){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no request body.");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    // concatnate chain buffer.
    char *body = ngx_chain_cat(r, r->request_body->bufs);
    if(!body){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient memory");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    am_web_handle_notification(body, strlen(body), agent_config);
    am_web_delete_agent_configuration(agent_config);
    agent_config = NULL;

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));
    cv.value = value;
    ngx_http_send_response(r, NGX_HTTP_OK, &type, &cv);
    return NGX_DONE;
}

static ngx_int_t
ngx_http_am_handler(ngx_http_request_t *r)
{
    am_status_t status;
    //am_web_result_t result;
    am_web_request_params_t req_params;
    am_web_request_func_t req_func;
    ngx_int_t err = NGX_ERROR;
    int ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
    void *args[2] = {r, &ret};
    ngx_http_am_ctx_t *ctx;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "ngx_http_am_handler()");

    // internal request is permitted unconditionally
    if(r->internal){
        return NGX_DECLINED;
    }

    // Fetch request body before processing the request (only if POST for now)
    ctx = ngx_http_get_module_ctx(r, ngx_http_am_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_am_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_am_module);
    }
    if (r->method == NGX_HTTP_POST && !ctx->waiting_more_body) {
        int rc = ngx_http_read_client_request_body(r, ngx_http_am_read_body_handler);
        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
            return rc;
        }
    }

    if(agent_initialized == B_FALSE){
        // No need to lock, Bravo NGINX!
        status = am_agent_init(&agent_initialized);
        if(status != AM_SUCCESS){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "am_agent_init error status=%s(%d)",
                          am_status_to_name(status), status);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if(!agent_config){
        agent_config = am_web_get_agent_configuration();
        if(!agent_config){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "error at am_web_get_agent_configuration()");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    err = ngx_http_am_setup_request_parms(r, &req_params);
    if(err == NGX_HTTP_NOT_ALLOWED){
        return err;
    }else if(err != NGX_OK){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error at ngx_http_am_setup_request_parms()");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if(am_web_is_notification(req_params.url, agent_config) == B_TRUE){
        // Hmmm, How I notify to all process when working multiprocess mode.
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "notification request.");
        ret = ngx_http_am_notification_handler(r);
        return ret;
    }

    if(ngx_http_am_setup_request_func(r, &req_func, args) != NGX_OK){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "error at ngx_http_am_setup_request_func()");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*result = */am_web_process_request(
        &req_params, &req_func, &status, agent_config);
    if(status != AM_SUCCESS){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "am_web_process_request error. "
                      "status=%s(%d)", am_status_to_name(status), status);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx->waiting_more_body) {
        ngx_http_finalize_request(r, NGX_DONE);
    }

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
