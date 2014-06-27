/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Derived from mod_remoteip.c.
 * Default values for directives are hard-wired for VG defaults.
 *
 * Supported directives and defaults:
 *
 * VGIPHeader X-Forwarded-For
 * VGTrustedProxy 10.84.0.0/16
 *
 * Version 1.0.0
 */

#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_lib.h"
#define APR_WANT_BYTEFUNC
#include "apr_want.h"
#include "apr_network_io.h"

module AP_MODULE_DECLARE_DATA vgremoteip_module;

#define VG_DEFAULT_IP_HEADER "X-Forwarded-For"
#define VG_DEFAULT_TRUSTED_PROXY {"10.84.0.0/16"}
#define VG_DEFAULT_TRUSTED_PROXY_COUNT 1

typedef struct {
		/** A proxy IP mask to match */
		apr_ipsubnet_t *ip;
} vgremoteip_proxymatch_t;

typedef struct {
		/** The header to retrieve a proxy-via ip list */
		const char *header_name;
		/** A header to record the proxied IP's
		 * (removed as the physical connection and
		 * from the proxy-via ip header value list)
		 */
		const char *proxies_header_name;
		/** A list of trusted proxies, ideally configured
		 *  with the most commonly encountered listed first
		 */
		apr_array_header_t *proxymatch_ip;
} vgremoteip_config_t;

typedef struct {
		/** The previous proxy-via request header value */
		const char *prior_remote;
		/** The unmodified original ip and address */
		const char *orig_ip;
		apr_sockaddr_t *orig_addr;
		/** The list of proxy ip's ignored as remote ip's */
		const char *proxy_ips;
		/** The remaining list of untrusted proxied remote ip's */
		const char *proxied_remote;
		/** The most recently modified ip and address record */
		const char *proxied_ip;
		apr_sockaddr_t proxied_addr;
} vgremoteip_conn_t;

typedef struct {
		conn_rec *saved_connection;
		char *saved_remote_ip;
		char *saved_remote_host;
} vgremoteip_proxy_save_rec_t;

static apr_status_t restore_proxy_remote_addr(void *data) {
		vgremoteip_proxy_save_rec_t *proxy_saved = (vgremoteip_proxy_save_rec_t *)data;

		conn_rec *conn = proxy_saved->saved_connection;

		conn->remote_ip = proxy_saved->saved_remote_ip;
		conn->remote_addr->sa.sin.sin_addr.s_addr = apr_inet_addr(conn->remote_ip);
		conn->remote_host = proxy_saved->saved_remote_host;

		return APR_SUCCESS;
}

static apr_status_t set_cf_default_proxies(apr_pool_t *p, vgremoteip_config_t *config);

static void *create_vgremoteip_server_config(apr_pool_t *p, server_rec *s) {
		vgremoteip_config_t *config = apr_pcalloc(p, sizeof *config);

		if (config == NULL) {
				return NULL;
		}

		if (set_cf_default_proxies(p, config) != APR_SUCCESS) {
				return NULL;
		}

		config->header_name = VG_DEFAULT_IP_HEADER;
		return config;
}

static void *merge_vgremoteip_server_config(apr_pool_t *p, void *globalv, void *serverv) {
		vgremoteip_config_t *global = (vgremoteip_config_t *) globalv;
		vgremoteip_config_t *server = (vgremoteip_config_t *) serverv;
		vgremoteip_config_t *config;

		config = (vgremoteip_config_t *) apr_palloc(p, sizeof(*config));
		config->header_name = server->header_name
				? server->header_name
				: global->header_name;
		config->proxies_header_name = server->proxies_header_name
				? server->proxies_header_name
				: global->proxies_header_name;
		config->proxymatch_ip = server->proxymatch_ip
				? server->proxymatch_ip
				: global->proxymatch_ip;
		return config;
}

static const char *header_name_set(cmd_parms *cmd, void *dummy, const char *arg) {
		vgremoteip_config_t *config = ap_get_module_config(cmd->server->module_config, &vgremoteip_module);
		config->header_name = apr_pstrdup(cmd->pool, arg);
		return NULL;
}

/* Would be quite nice if APR exported this */
/* apr:network_io/unix/sockaddr.c */
static int looks_like_ip(const char *ipstr) {
		if (ap_strchr_c(ipstr, ':')) {
				/* definitely not a hostname; assume it is intended to be an IPv6 address */
				return 1;
		}

		/* simple IPv4 address string check */
		while ((*ipstr == '.') || apr_isdigit(*ipstr))
				ipstr++;
		return (*ipstr == '\0');
}

static apr_status_t set_cf_default_proxies(apr_pool_t *p, vgremoteip_config_t *config)
{
		apr_status_t rv;
		vgremoteip_proxymatch_t *match;
		int i;
		char *proxies[] = VG_DEFAULT_TRUSTED_PROXY;

		for (i=0; i<VG_DEFAULT_TRUSTED_PROXY_COUNT; i++) {
				char *ip = apr_pstrdup(p, proxies[i]);
				char *s = ap_strchr(ip, '/');

				if (s) {
						*s++ = '\0';
				}
				if (!config->proxymatch_ip) {
						config->proxymatch_ip = apr_array_make(p, 1, sizeof(*match));
				}

				match = (vgremoteip_proxymatch_t *) apr_array_push(config->proxymatch_ip);
				rv = apr_ipsubnet_create(&match->ip, ip, s, p);
		}
		return rv;
}

static const char *proxies_set(cmd_parms *cmd, void *param, const char *arg) {
		vgremoteip_config_t *config = ap_get_module_config(cmd->server->module_config, &vgremoteip_module);
		vgremoteip_proxymatch_t *match;
		apr_status_t rv;

		char *ip = apr_pstrdup(cmd->temp_pool, arg);
		char *s = ap_strchr(ip, '/');

		if (s) {
	    *s++ = '\0';
    }

		if (!config->proxymatch_ip) config->proxymatch_ip = apr_array_make(cmd->pool, 1, sizeof(*match));

		match = (vgremoteip_proxymatch_t *) apr_array_push(config->proxymatch_ip);

		if (looks_like_ip(ip)) {
				/* Note s may be null, that's fine (explicit host) */
				rv = apr_ipsubnet_create(&match->ip, ip, s, cmd->pool);
		} else {
				apr_sockaddr_t *temp_sa;

				if (s) {
						return apr_pstrcat(cmd->pool, "RemoteIP: Error parsing IP ", arg,
										" the subnet /", s, " is invalid for ",
										cmd->cmd->name, NULL);
				}

				rv = apr_sockaddr_info_get(&temp_sa,  ip, APR_UNSPEC, 0,
								APR_IPV4_ADDR_OK, cmd->temp_pool);
				while (rv == APR_SUCCESS) {
						apr_sockaddr_ip_get(&ip, temp_sa);
						rv = apr_ipsubnet_create(&match->ip, ip, NULL, cmd->pool);
						if (!(temp_sa = temp_sa->next))
								break;
						match = (vgremoteip_proxymatch_t *)
								apr_array_push(config->proxymatch_ip);
				}
		}

		if (rv != APR_SUCCESS) {
				char msgbuf[128];
				apr_strerror(rv, msgbuf, sizeof(msgbuf));
				return apr_pstrcat(cmd->pool, "RemoteIP: Error parsing IP ", arg,
								" (", msgbuf, " error) for ", cmd->cmd->name, NULL);
		}

		return NULL;
}

/* Returns true if ip is within a allowed proxy subnet, false otherwise. */
int isVGProxy(vgremoteip_config_t *config, apr_sockaddr_t *ip) {
		int i;
		vgremoteip_proxymatch_t *match;

		match = (vgremoteip_proxymatch_t *)config->proxymatch_ip->elts;   
		for (i = 0; i < config->proxymatch_ip->nelts; i++) {
				if (apr_ipsubnet_test(match[i].ip, ip)) {
						return 1;
				}
		}

		return 0;
}

static int vgremoteip_modify_connection(request_rec *r) {
		conn_rec *c = r->connection;
		vgremoteip_config_t *config;
		vgremoteip_proxy_save_rec_t *proxy_saved;
		apr_sockaddr_t *clientaddr = NULL, *tempaddr = NULL;
		apr_array_header_t *ipList;
		int i;
		const char *remote;
		char *curVal = NULL, *clientip = NULL;

		config = ap_get_module_config(r->server->module_config, &vgremoteip_module);
		remote = (char *) apr_table_get(r->headers_in, config->header_name);

		apr_sockaddr_ip_get(&clientip, c->remote_addr); 

		/* If the request is not orginating from an allowed proxy then just return OK and do not modify the connection. */
		if (!isVGProxy(config, c->remote_addr)) {
				return OK;
		}

		/* If the Client-IP header is not set, just return OK. */
		if (!remote) {
				return OK;
		}

		/* Just a security measure. */
		if (strlen(remote) > 256) {
				return OK;
		}

		remote = apr_pstrdup(r->pool, remote);
		ipList = apr_array_make(r->pool, 1, sizeof(char*));

		while (*remote && (curVal = ap_get_token(r->pool, &remote, 0))) {
				if (looks_like_ip(curVal)) {
						*(char**)apr_array_push(ipList) = apr_pstrdup(r->pool, curVal); /* Add IP to array. */
				}

				if (*remote == ',' || *remote == ';') ++remote;
		}

		/* If there are no ip's in the list just return OK. */
		if (ipList->nelts < 1) return OK;

		if (ipList->nelts == 1) {
				/* We only got one addr in list, use that even if it is a proxy. */
				if (apr_sockaddr_info_get(&clientaddr, ((char**)ipList->elts)[0], APR_UNSPEC, 0, APR_IPV4_ADDR_OK, r->pool) != APR_SUCCESS) 
						return OK;
		} else { /* More than one ip in the list. */
				for (i = ipList->nelts-1; i >= 0; i--) {
						if (apr_sockaddr_info_get(&tempaddr, ((char**)ipList->elts)[i], APR_UNSPEC, 0, APR_IPV4_ADDR_OK, r->pool) != APR_SUCCESS) 
								continue;

						if (!isVGProxy(config, tempaddr)) {
								clientaddr = tempaddr;
						}
				}
		} 

		if (clientaddr != NULL) {
				/* Register cleanup handler. */
				proxy_saved = apr_pcalloc(r->pool, sizeof(vgremoteip_proxy_save_rec_t));
				proxy_saved->saved_connection = r->connection;
				proxy_saved->saved_remote_ip = r->connection->remote_ip;
				proxy_saved->saved_remote_host = r->connection->remote_host;
				apr_pool_cleanup_register(r->pool, (void *)proxy_saved, restore_proxy_remote_addr, apr_pool_cleanup_null);

				/* Set PROXY_ADDR environment variable. */
				apr_table_set(r->subprocess_env, "PROXY_ADDR", c->remote_ip);

				/* Get the IP address. */
				if (apr_sockaddr_ip_get(&clientip, clientaddr) != APR_SUCCESS)
						return OK;

				/* Do the actual spoof. */
				c->remote_ip = apr_pstrdup(r->pool, clientip);
				c->remote_addr = clientaddr;
				c->remote_host = apr_pstrdup(r->pool, ap_get_remote_host(c, r->per_dir_config, REMOTE_HOST, NULL));
		}

		return OK;
}

static const command_rec vgremoteip_cmds[] = 
{
		AP_INIT_TAKE1("VGRemoteIPHeader", header_name_set, NULL, RSRC_CONF,
						"Specifies a request header to trust as the client IP, "
						"Overrides the default of X-Forwarded-For"),
		AP_INIT_ITERATE("VGTrustedProxy", proxies_set, NULL, RSRC_CONF,
						"Specifies one or more proxies which are trusted "
						"to present IP headers. Overrides the defaults."),
		{ NULL }
};

static void register_hooks(apr_pool_t *p) {
		// We need to run very early so as to not trip up mod_security. 
		// Hence, this little trick, as mod_security runs at APR_HOOK_REALLY_FIRST.
		ap_hook_post_read_request(vgremoteip_modify_connection, NULL, NULL, APR_HOOK_REALLY_FIRST - 10);
}

module AP_MODULE_DECLARE_DATA vgremoteip_module = {
		STANDARD20_MODULE_STUFF,
		NULL,                            /* create per-directory config structure */
		NULL,                            /* merge per-directory config structures */
		create_vgremoteip_server_config, /* create per-server config structure */
		merge_vgremoteip_server_config,  /* merge per-server config structures */
		vgremoteip_cmds,                 /* command apr_table_t */
		register_hooks                   /* register hooks */
};
