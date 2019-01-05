/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * mod_auth_cas.c
 * Apache CAS Authentication Module
 * Version 1.0.8SFU
 *
 * Author:
 * Phil Ames       <modauthcas [at] gmail [dot] com>
 * Designers:
 * Phil Ames       <modauthcas [at] gmail [dot] com>
 * Matt Smith      <matt [dot] smith [at] uconn [dot] edu>
 * SFU Additions:
 * Ray Davison     <ray [at] sfu [dot] ca>
 */

/*
 * The SFU version of this module makes use of some private apache
 * stuff, so make sure it is available to us.
 */
#define CORE_PRIVATE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <sys/types.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_md5.h"
#include "ap_config.h"
#include "ap_release.h"
#include "apr_buckets.h"
#include "apr_file_info.h"
#include "apr_md5.h"
#include "apr_strings.h"
#include "apr_xml.h"
#include "apr_base64.h"         /* for apr_base64_decode et al */

#include "mod_auth_cas.h"

int cas_flock(apr_file_t *fileHandle, int lockOperation, request_rec *r)
{
	apr_os_file_t osFileHandle;
	int flockErr;

	apr_os_file_get(&osFileHandle, fileHandle);

	do {
		flockErr = flock(osFileHandle, lockOperation);
	} while(flockErr == -1 && errno == EINTR);

	if(r != NULL && flockErr) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Failed to apply locking operation (%s)", strerror(errno));
	}

	return flockErr;
}

/* mod_auth_cas configuration specific functions */
static void *cas_create_server_config(apr_pool_t *pool, server_rec *svr)
{
	cas_cfg *c = apr_pcalloc(pool, sizeof(cas_cfg));
	c->CASVersion = CAS_DEFAULT_VERSION;
	c->CASDebug = CAS_DEFAULT_DEBUG;
	c->CASValidateServer = CAS_DEFAULT_VALIDATE_SERVER;
	c->CASValidateDepth = CAS_DEFAULT_VALIDATE_DEPTH;
	c->CASAllowWildcardCert = CAS_DEFAULT_ALLOW_WILDCARD_CERT;
	c->CASCertificatePath = CAS_DEFAULT_CA_PATH;
	c->CASCookiePath = CAS_DEFAULT_COOKIE_PATH;
	c->CASCookieEntropy = CAS_DEFAULT_COOKIE_ENTROPY;
	c->CASTimeout = CAS_DEFAULT_COOKIE_TIMEOUT;
	c->CASIdleTimeout = CAS_DEFAULT_COOKIE_IDLE_TIMEOUT;
	c->CASCacheCleanInterval = CAS_DEFAULT_CACHE_CLEAN_INTERVAL;
	c->CASCookieDomain = CAS_DEFAULT_COOKIE_DOMAIN;
	c->CASCookieHttpOnly = CAS_DEFAULT_COOKIE_HTTPONLY;

	cas_setURL(pool, &(c->CASLoginURL), CAS_DEFAULT_LOGIN_URL);
	cas_setURL(pool, &(c->CASValidateURL), CAS_DEFAULT_VALIDATE_URL);
	cas_setURL(pool, &(c->CASProxyValidateURL), CAS_DEFAULT_PROXY_VALIDATE_URL);
	cas_setURL(pool, &(c->CASRootProxiedAs), CAS_DEFAULT_ROOT_PROXIED_AS_URL);
	cas_setURL(pool, &(c->CASTicketsURL), CAS_DEFAULT_TICKETS_URL);

	return c;
}

static void *cas_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD)
{
	cas_cfg *c = apr_pcalloc(pool, sizeof(cas_cfg));
	cas_cfg *base = BASE;
	cas_cfg *add = ADD;
	apr_uri_t test;
	memset(&test, '\0', sizeof(apr_uri_t));

	c->CASVersion = (add->CASVersion != CAS_DEFAULT_VERSION ? add->CASVersion : base->CASVersion);
	c->CASDebug = (add->CASDebug != CAS_DEFAULT_DEBUG ? add->CASDebug : base->CASDebug);
	c->CASValidateServer = (add->CASValidateServer != CAS_DEFAULT_VALIDATE_SERVER ? add->CASValidateServer : base->CASValidateServer);
	c->CASValidateDepth = (add->CASValidateDepth != CAS_DEFAULT_VALIDATE_DEPTH ? add->CASValidateDepth : base->CASValidateDepth);
	c->CASAllowWildcardCert = (add->CASAllowWildcardCert != CAS_DEFAULT_ALLOW_WILDCARD_CERT ? add->CASAllowWildcardCert : base->CASAllowWildcardCert);
	c->CASCertificatePath = (apr_strnatcasecmp(add->CASCertificatePath,CAS_DEFAULT_CA_PATH) != 0 ? add->CASCertificatePath : base->CASCertificatePath);
	c->CASCookiePath = (apr_strnatcasecmp(add->CASCookiePath, CAS_DEFAULT_COOKIE_PATH) != 0 ? add->CASCookiePath : base->CASCookiePath);
	c->CASCookieEntropy = (add->CASCookieEntropy != CAS_DEFAULT_COOKIE_ENTROPY ? add->CASCookieEntropy : base->CASCookieEntropy);
	c->CASTimeout = (add->CASTimeout != CAS_DEFAULT_COOKIE_TIMEOUT ? add->CASTimeout : base->CASTimeout);
	c->CASIdleTimeout = (add->CASIdleTimeout != CAS_DEFAULT_COOKIE_IDLE_TIMEOUT ? add->CASIdleTimeout : base->CASIdleTimeout);
	c->CASCacheCleanInterval = (add->CASCacheCleanInterval != CAS_DEFAULT_CACHE_CLEAN_INTERVAL ? add->CASCacheCleanInterval : base->CASCacheCleanInterval);
	c->CASCookieDomain = (add->CASCookieDomain != CAS_DEFAULT_COOKIE_DOMAIN ? add->CASCookieDomain : base->CASCookieDomain);
	c->CASCookieHttpOnly = (add->CASCookieHttpOnly != CAS_DEFAULT_COOKIE_HTTPONLY ? add->CASCookieHttpOnly : base->CASCookieHttpOnly);

	/* if add->CASLoginURL == NULL, we want to copy base -- otherwise, copy the one from add, and so on and so forth */
	if(memcmp(&add->CASLoginURL, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->CASLoginURL, &base->CASLoginURL, sizeof(apr_uri_t));
	else
		memcpy(&c->CASLoginURL, &add->CASLoginURL, sizeof(apr_uri_t));

	if(memcmp(&add->CASValidateURL, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->CASValidateURL, &base->CASValidateURL, sizeof(apr_uri_t));
	else
		memcpy(&c->CASValidateURL, &add->CASValidateURL, sizeof(apr_uri_t));

	if(memcmp(&add->CASProxyValidateURL, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->CASProxyValidateURL, &base->CASProxyValidateURL, sizeof(apr_uri_t));
	else
		memcpy(&c->CASProxyValidateURL, &add->CASProxyValidateURL, sizeof(apr_uri_t));

	if(memcmp(&add->CASRootProxiedAs, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->CASRootProxiedAs, &base->CASRootProxiedAs, sizeof(apr_uri_t));
	else
		memcpy(&c->CASRootProxiedAs, &add->CASRootProxiedAs, sizeof(apr_uri_t));

	if(memcmp(&add->CASTicketsURL, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->CASTicketsURL, &base->CASTicketsURL, sizeof(apr_uri_t));
	else
		memcpy(&c->CASTicketsURL, &add->CASTicketsURL, sizeof(apr_uri_t));

	return c;
}

static void *cas_create_dir_config(apr_pool_t *pool, char *path)
{
	cas_dir_cfg *c = apr_pcalloc(pool, sizeof(cas_dir_cfg));
	c->CASScope = CAS_DEFAULT_SCOPE;
	c->CASRenew = CAS_DEFAULT_RENEW;
	c->CASGateway = CAS_DEFAULT_GATEWAY;
	c->CASCookie = CAS_DEFAULT_COOKIE;
	c->CASSecureCookie = CAS_DEFAULT_SCOOKIE;
	c->CASGatewayCookie = CAS_DEFAULT_GATEWAY_COOKIE;
	c->CASAuthNHeader = CAS_DEFAULT_AUTHN_HEADER;
	/* SFU specific stuff */
	c->authtype = CAS_DEFAULT_AUTHTYPE;
	c->maillist = CAS_DEFAULT_MAILLIST;
	c->password = CAS_DEFAULT_PASSWORD;
	c->pwfile = CAS_DEFAULT_PWFILE;
	c->gpfile = CAS_DEFAULT_GPFILE;
	c->authoritative = CAS_DEFAULT_AUTHORITATIVE;
	c->haveTicket = 0;
	c->useauthtype = CAS_DEFAULT_USEAUTHTYPE;
	c->CASAuthTypeHeader = CAS_DEFAULT_AUTHTYPE_HEADER;
	c->CASAuthMaillistHeader = CAS_DEFAULT_MAILLIST_HEADER;
	return(c);
}

static void *cas_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD)
{
	cas_dir_cfg *c = apr_pcalloc(pool, sizeof(cas_dir_cfg));
	cas_dir_cfg *base = BASE;
	cas_dir_cfg *add = ADD;

	/* inherit the previous directory's setting if applicable */
	c->CASScope = (add->CASScope != CAS_DEFAULT_SCOPE ? add->CASScope : base->CASScope);
	if(add->CASScope != NULL && strcasecmp(add->CASScope, "Off") == 0)
		c->CASScope = NULL;

	c->CASRenew = (add->CASRenew != CAS_DEFAULT_RENEW ? add->CASRenew : base->CASRenew);
	if(add->CASRenew != NULL && strcasecmp(add->CASRenew, "Off") == 0)
		c->CASRenew = NULL;

	c->CASGateway = (add->CASGateway != CAS_DEFAULT_GATEWAY ? add->CASGateway : base->CASGateway);
	if(add->CASGateway != NULL && strcasecmp(add->CASGateway, "Off") == 0)
		c->CASGateway = NULL;

	c->CASCookie = (apr_strnatcasecmp(add->CASCookie, CAS_DEFAULT_COOKIE) != 0 ? add->CASCookie : base->CASCookie);
	c->CASSecureCookie = (apr_strnatcasecmp(add->CASSecureCookie, CAS_DEFAULT_SCOOKIE) != 0 ? add->CASSecureCookie : base->CASSecureCookie);
	c->CASGatewayCookie = (apr_strnatcasecmp(add->CASGatewayCookie, CAS_DEFAULT_GATEWAY_COOKIE) != 0 ? add->CASGatewayCookie : base->CASGatewayCookie);
	
	c->CASAuthNHeader = (apr_strnatcasecmp(add->CASAuthNHeader, CAS_DEFAULT_AUTHN_HEADER) != 0 ? add->CASAuthNHeader : base->CASAuthNHeader);
	/* SFU Extensions */
	c->authtype = add->authtype;
	c->maillist = add->maillist;
	c->password = add->password;
	c->pwfile = (add->pwfile != CAS_DEFAULT_PWFILE ? add->pwfile : base->pwfile);
	c->gpfile = (add->gpfile != CAS_DEFAULT_GPFILE ? add->gpfile : base->gpfile);
	c->authoritative = (add->authoritative != CAS_DEFAULT_AUTHORITATIVE ? add->authoritative : base->authoritative);
	c->haveTicket = add->haveTicket;
	c->useauthtype = (add->useauthtype != CAS_DEFAULT_USEAUTHTYPE ? add->useauthtype : base->useauthtype);
	c->CASAuthTypeHeader = (apr_strnatcasecmp(add->CASAuthTypeHeader, CAS_DEFAULT_AUTHTYPE_HEADER) != 0 ? add->CASAuthTypeHeader : base->CASAuthTypeHeader);
	c->CASAuthMaillistHeader = (apr_strnatcasecmp(add->CASAuthMaillistHeader, CAS_DEFAULT_MAILLIST_HEADER) != 0 ? add->CASAuthMaillistHeader : base->CASAuthMaillistHeader);
	return(c);
}

static const char *cfg_readCASParameter(cmd_parms *cmd, void *cfg, const char *value)
{
	cas_cfg *c = (cas_cfg *) ap_get_module_config(cmd->server->module_config, &auth_cas_module);
	apr_finfo_t f;
	int i;
	char d;

	/* cases determined from valid_cmds in mod_auth_cas.h - the config at this point is initialized to default values */
	switch((size_t) cmd->info) {
		case cmd_version:
			i = atoi(value);
			if(i > 0)
				c->CASVersion = i;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid CAS version (%s) specified", value));
		break;
		case cmd_debug:
			/* if atoi() is used on value here with AP_INIT_FLAG, it works but results in a compile warning, so we use TAKE1 to avoid it */
			if(apr_strnatcasecmp(value, "On") == 0)
				c->CASDebug = TRUE;
			else if(apr_strnatcasecmp(value, "Off") == 0)
				c->CASDebug = FALSE;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid argument to CASDebug - must be 'On' or 'Off'"));
		break;
		case cmd_validate_server:
			/* if atoi() is used on value here with AP_INIT_FLAG, it works but results in a compile warning, so we use TAKE1 to avoid it */
			if(apr_strnatcasecmp(value, "On") == 0)
				c->CASValidateServer = TRUE;
			else if(apr_strnatcasecmp(value, "Off") == 0)
				c->CASValidateServer = FALSE;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid argument to CASValidateServer - must be 'On' or 'Off'"));
		break;
		case cmd_wildcard_cert:
			/* if atoi() is used on value here with AP_INIT_FLAG, it works but results in a compile warning, so we use TAKE1 to avoid it */
			if(apr_strnatcasecmp(value, "On") == 0)
				c->CASAllowWildcardCert = TRUE;
			else if(apr_strnatcasecmp(value, "Off") == 0)
				c->CASAllowWildcardCert = FALSE;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid argument to CASValidateServer - must be 'On' or 'Off'"));
		break;

		case cmd_ca_path:
			if(apr_stat(&f, value, APR_FINFO_TYPE, cmd->temp_pool) == APR_INCOMPLETE)
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Could not find Certificate Authority file '%s'", value));
	
			if(f.filetype != APR_REG && f.filetype != APR_DIR)
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Certificate Authority file '%s' is not a regular file or directory", value));
			c->CASCertificatePath = apr_pstrdup(cmd->pool, value);
		break;
		case cmd_validate_depth:
			i = atoi(value);
			if(i > 0)
				c->CASValidateDepth = i;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid CASValidateDepth (%s) specified", value));
		break;

		case cmd_cookie_path:
			/* this is probably redundant since the same check is performed in cas_post_config */
			if(apr_stat(&f, value, APR_FINFO_TYPE, cmd->temp_pool) == APR_INCOMPLETE)
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Could not find CASCookiePath '%s'", value));
			
			if(f.filetype != APR_DIR || value[strlen(value)-1] != '/')
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: CASCookiePath '%s' is not a directory or does not end in a trailing '/'!", value));
			c->CASCookiePath = apr_pstrdup(cmd->pool, value);
		break;

		case cmd_loginurl:
			if(cas_setURL(cmd->pool, &(c->CASLoginURL), value) != TRUE)
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Login URL '%s' could not be parsed!", value));
		break;
		case cmd_validateurl:
			if(cas_setURL(cmd->pool, &(c->CASValidateURL), value) != TRUE)
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Validation URL '%s' could not be parsed!", value));
		break;
		case cmd_proxyurl:
			if(cas_setURL(cmd->pool, &(c->CASProxyValidateURL), value) != TRUE)
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Proxy Validation URL '%s' could not be parsed!", value));
		break;
		case cmd_root_proxied_as:
			if(cas_setURL(cmd->pool, &(c->CASRootProxiedAs), value) != TRUE)
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Root Proxy URL '%s' could not be parsed!", value));
		break;
		case cmd_ticketsurl:
			if(cas_setURL(cmd->pool, &(c->CASTicketsURL), value) != TRUE)
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Tickets URL '%s' could not be parsed!", value));
		break;
		case cmd_cookie_entropy:
			i = atoi(value);
			if(i > 0)
				c->CASCookieEntropy = i;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid CASCookieEntropy (%s) specified - must be numeric", value));
		break;
		case cmd_session_timeout:
			i = atoi(value);
			if(i > 0)
				c->CASTimeout = i;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid CASTimeout (%s) specified - must be numeric", value));
		break;
		case cmd_idle_timeout:
			i = atoi(value);
			if(i > 0)
				c->CASIdleTimeout = i;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid CASIdleTimeout (%s) specified - must be numeric", value));
		break;

		case cmd_cache_interval:
			i = atoi(value);
			if(i > 0)
				c->CASCacheCleanInterval = i;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid CASCacheCleanInterval (%s) specified - must be numeric", value));
		break;
		case cmd_cookie_domain:
			for(i = 0; i < strlen(value); i++) {
				d = value[i];
				if( (d < '0' || d > '9') && 
					(d < 'a' || d > 'z') &&
					(d < 'A' || d > 'Z') &&
					d != '.' && d != '-') {
						return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid character (%c) in CASCookieDomain", d));
				}
			}
			c->CASCookieDomain = apr_pstrdup(cmd->pool, value);
		break;
		case cmd_cookie_httponly:
			if(apr_strnatcasecmp(value, "On") == 0)
				c->CASCookieHttpOnly = TRUE;
			else if(apr_strnatcasecmp(value, "Off") == 0)
				c->CASCookieHttpOnly = FALSE;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid argument to CASCookieHttpOnly - must be 'On' or 'Off'"));

		break;
		case cmd_CAS_authtype: {
			cas_dir_cfg *d = (cas_dir_cfg *)cfg;
			if(apr_strnatcasecmp(value, "CAS") == 0)
				d->useauthtype = CAS_AUTHTYPE_CAS;
			else if(apr_strnatcasecmp(value, "Basic") == 0)
				d->useauthtype = CAS_AUTHTYPE_BASIC;
			else if(apr_strnatcasecmp(value, "Both") == 0)
				d->useauthtype = CAS_AUTHTYPE_BOTH;
			else
				return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: Invalid argument to CASAuthType - must be 'CAS', 'Basic' or 'Both'"));
		}
		break;
		default:
			/* should not happen */
			return(apr_psprintf(cmd->pool, "MOD_AUTH_CAS: invalid command '%s'", cmd->directive->directive));
		break;
	}
	return NULL;
}

/* utility functions to set/retrieve values from the configuration */
static apr_byte_t cas_setURL(apr_pool_t *pool, apr_uri_t *uri, const char *url)
{

	if(url == NULL) {
		uri = apr_pcalloc(pool, sizeof(apr_uri_t));
		return FALSE;
	}

	if(apr_uri_parse(pool, url, uri) != APR_SUCCESS)
		return FALSE;
	/* set a default port if none was specified - we need this to perform a connect() to these servers for validation later */
	if(uri->port == 0)
		uri->port = apr_uri_port_of_scheme(uri->scheme);
	if(uri->hostname == NULL)
		return FALSE;


	return TRUE;
}

static apr_byte_t isSSL(request_rec *r)
{

#ifdef APACHE2_0
	if(apr_strnatcasecmp("https", ap_http_method(r)) == 0)
#else
	if(apr_strnatcasecmp("https", ap_http_scheme(r)) == 0)
#endif
		return TRUE;

	return FALSE;
}

/* r->parsed_uri.path will return something like /xyz/index.html - this removes the file portion */
static char *getCASPath(request_rec *r)
{
	char *p = r->parsed_uri.path, *rv;
	size_t i, l = 0;
	for(i = 0; i < strlen(p); i++) {
		if(p[i] == '/')
			l = i;
	}
        rv = apr_pstrndup(r->pool, p, (l+1));
	return(rv);
}

static char *getCASScope(request_rec *r)
{
	char *rv = NULL, *requestPath = getCASPath(r);
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Determining CAS scope (path: %s, CASScope: %s, CASRenew: %s, CASGateway: %s)", requestPath, d->CASScope, d->CASRenew, d->CASGateway);

	if (d->CASGateway != NULL) {
		/* the gateway path should be a subset of the request path */
		if(strncmp(d->CASGateway, requestPath, strlen(d->CASGateway)) == 0)
			rv = d->CASGateway;
		else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: CASGateway (%s) not a substring of request path, using request path (%s) for cookie", d->CASGateway, requestPath);
			rv = requestPath;
		}
	}

	if(d->CASRenew != NULL) {
		if(rv != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: CASRenew (%s) and CASGateway (%s) set, CASRenew superceding.", d->CASRenew, d->CASGateway);
		}
		if(strncmp(d->CASRenew, requestPath, strlen(d->CASRenew)) == 0)
			rv = d->CASRenew;
		else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: CASRenew (%s) not a substring of request path, using request path (%s) for cookie", d->CASRenew, requestPath);
			rv = requestPath;
		}

	}

	/* neither gateway nor renew was set */
	if(rv == NULL) {
		if(d->CASScope != NULL) {
			if(strncmp(d->CASScope, requestPath, strlen(d->CASScope)) == 0)
				rv = d->CASScope;
			else {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: CASScope (%s) not a substring of request path, using request path (%s) for cookie", d->CASScope, requestPath);
				rv = requestPath;
			}
		}
		else
			rv = requestPath;
	}

	return (rv);
}

static char *getCASGateway(request_rec *r)
{
	char *rv = "";
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering getCASGateway()");

	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
	if(d->CASGateway != NULL && strncmp(d->CASGateway, r->parsed_uri.path, strlen(d->CASGateway)) == 0 && c->CASVersion > 1) { /* gateway not supported in CAS v1 */
		rv = "&gateway=true";
	}
	return rv;
}

static char *getCASRenew(request_rec *r)
{
	char *rv = "";
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
	if(d->CASRenew != NULL && strncmp(d->CASRenew, r->parsed_uri.path, strlen(d->CASRenew)) == 0) {
		rv = "&renew=true";
	}
	return rv;
}

static char *getCASretry(request_rec *r) {
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
	if (d->haveTicket == 1) {
		return "&renew=true&error=The+credentials+you+provided+are+not+authorized+to+access+this+site.+Correct+your+ID+and+password+and+try+again.";
	} else {
		return "";
	}
}

static char *getRealmAsMessage(request_rec *r) {
	// If the user has set a realm (by setting AuthName in the htaccess or configuration file), this module will
	// use this to set a message on the login page.
	const char *message = ap_auth_name(r);
	if (message) {
		return apr_pstrcat(r->pool, "&message=", message, NULL);
	}
	return "";
}

// It builds the "allow" string before redirecting to CAS login
static char *getCASAllow(request_rec *r) {
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

	// The following is used to put together the allow string 
	int allowSFU=0;       // standard SFU accounts
	int allowAlumni=0;    // alumni accounts
	int allowApache=0;    // accounts from a .htpasswd file
	int allowStaff=0;     // a staff SFU account
	int allowStudent=0;   // a student SFU account
	int allowFaculty=0;   // a faculty SFU account
	int allowSponsored=0; // a sponsored SFU account
	int allowExternal=0;  // an external SFU account
	char *allowString = "";

	/* Look at the type of users that are allowed into this page so that we can let CAS know */
#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211
	// Always add "allow=sfu"
	allowSFU=1;
#else
	const apr_array_header_t *requirements_array = ap_requires(r);
	if (requirements_array) {
		require_line *requirements = (require_line *) requirements_array->elts;
		int method = r->method_number;

		int i;
		for (i = 0; i < requirements_array->nelts; i++) {
			const char *req_line, *req_word;
			// if our method isn't covered by the requirements line, ignore it
			if (!(requirements[i].method_mask & (1 << method))) continue;
			req_line = requirements[i].requirement;		// full line
			req_word = ap_getword(r->pool, &req_line, ' ');	// individual word
			if (!strcasecmp(req_word, "valid-sfu-user")) {
				// Allow any SFU account
				allowSFU = 1;
				continue;
			}
			if (!strcasecmp(req_word, "valid-sfu-staff")) {
				// Allow any SFU staff account
				if (allowStaff) continue;
				allowString = apr_pstrcat(r->pool, allowString, ",staff", NULL);
				allowStaff = 1;
				continue;
			}
			if (!strcasecmp(req_word, "valid-sfu-faculty")) {
				// Allow any SFU faculty account
				if (allowFaculty) continue;
				allowString = apr_pstrcat(r->pool, allowString, ",faculty", NULL);
				allowFaculty = 1;
				continue;
			}
			if (!strcasecmp(req_word, "valid-sfu-student")) {
				// Allow any SFU student account
				if (allowStudent) continue;
				allowString = apr_pstrcat(r->pool, allowString, ",student", NULL);
				allowStudent = 1;
				continue;
			}
			if (!strcasecmp(req_word, "valid-sfu-sponsored")) {
				// Allow any SFU sponsored account
				if (allowSponsored) continue;
				allowString = apr_pstrcat(r->pool, allowString, ",sponsored", NULL);
				allowSponsored = 1;
				continue;
			}
			if (!strcasecmp(req_word, "valid-sfu-external")) {
				// Allow any SFU external account
				if (allowExternal) continue;
				allowString = apr_pstrcat(r->pool, allowString, ",external", NULL);
				allowExternal = 1;
				continue;
			}
			if (!strcasecmp(req_word, "sfu-user")) {
				// check each entry to see if maillists are specified
				while (*req_line) {
					req_word = ap_getword_conf(r->pool, &req_line);
					if (req_word[0]=='!') {
						// a mail list. Add it to the allow list
						allowString = apr_pstrcat(r->pool, allowString, ",", req_word, NULL);
						continue;
					} else {
						// Allow any SFU account
						allowSFU = 1;
						continue;
					}
				}
				continue;
			}
			if (!strcasecmp(req_word, "valid-alumni-user") || !strcasecmp(req_word, "alumni-user")) {
				// allow alumni user
				if (allowAlumni) continue;
				allowString = apr_pstrcat(r->pool, allowString, ",alumni", NULL);
				allowAlumni = 1;
				continue;
			}
			if (!strcasecmp(req_word, "user") || !strcasecmp(req_word, "valid-user")) {
				// Normally user and valid-user refers to items in the password file, but if there isn't 
				// a password file specified, treat them as valid-sfu-user
				if (!d->pwfile) {
					allowSFU = 1;
					continue;
				}				
			}
		}
	}
#endif
	{
		// Process the .htpasswd
		ap_configfile_t *f;
		/* Check in the password file for users */
		if (d->pwfile) {
			char l[CAS_MAX_RESPONSE_SIZE+1];
			
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "getCASAllow: Trying to open htpasswd file '%s'", d->pwfile==NULL?"(NULL)":d->pwfile);
			if (APR_SUCCESS == ap_pcfg_openfile(&f, r->pool, d->pwfile)) {
				if (c->CASDebug)
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "getCASAllow: Successfully opened '%s'", d->pwfile);
				
				while (!(ap_cfg_getline(l, CAS_MAX_RESPONSE_SIZE, f))) {
					if (c->CASDebug)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "getCASAllow: password file line '%s'", l);
					if ((l[0] == '#') || (!l[0])) continue; // ignore comment or blank lines
					if (l[0] == '+') {
						if (l[1] == '!') {
							// a mail list. Add it to the allow list
							allowString = apr_pstrcat(r->pool, allowString, ",", l+1, NULL);
						} else {
							// Allow any SFU account
							allowSFU = 1;
						}
					} else {
						// a local (apache) account
						allowApache = 1;
					}
				}
				ap_cfg_closefile(f);
			}
		}
	}
	// allowSFU is always 1 for 2.4 
	// allowSFU is not always 1 for 2.2
	if (allowSFU) {
		allowString = apr_pstrcat(r->pool, allowString, ",sfu", NULL);
	}
	if (allowApache) {
		allowString = apr_pstrcat(r->pool, allowString, ",apache", NULL);
	}
	// If we don't have an allow string, set it to the default
	if (!allowString[0]) return "";
	
	return apr_pstrcat(r->pool, "&allow=", allowString+1, NULL);
}

static char *getCASValidateURL(request_rec *r, cas_cfg *c)
{
	apr_uri_t test;

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering getCASValidateURL()");

	memset(&test, '\0', sizeof(apr_uri_t));
	if(memcmp(&c->CASValidateURL, &test, sizeof(apr_uri_t)) == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: CASValidateURL null (not set?)");
		return NULL;
	}
	/* this is used in the 'GET /[validateURL]...' context */
	return(apr_uri_unparse(r->pool, &(c->CASValidateURL), APR_URI_UNP_OMITSITEPART|APR_URI_UNP_OMITUSERINFO|APR_URI_UNP_OMITQUERY));

}

static char *getCASLoginURL(request_rec *r, cas_cfg *c)
{
	apr_uri_t test;

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering getCASLoginURL()");

	memset(&test, '\0', sizeof(apr_uri_t));
	if(memcmp(&c->CASLoginURL, &test, sizeof(apr_uri_t)) == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: CASLoginURL null (not set?)");
		return NULL;
	}
	/* this is used in the 'Location: [LoginURL]...' header context */
	return(apr_uri_unparse(r->pool, &(c->CASLoginURL), APR_URI_UNP_OMITUSERINFO|APR_URI_UNP_OMITQUERY));
}

static char *getCASTicketsURL(request_rec *r, cas_cfg *c)
{
	apr_uri_t test;

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering getCASTicketsURL()");

	memset(&test, '\0', sizeof(apr_uri_t));
	if(memcmp(&c->CASTicketsURL, &test, sizeof(apr_uri_t)) == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: CASTicketsURL null (not set?)");
		return NULL;
	}
	/* this is used in the 'GET: [ticketsURL]...' context */
	return(apr_uri_unparse(r->pool, &(c->CASTicketsURL), APR_URI_UNP_OMITSITEPART|APR_URI_UNP_OMITUSERINFO|APR_URI_UNP_OMITQUERY));
}

/*
 * Create the 'service=...' parameter
 * The reason this is not an apr_uri_t based on r->parsed_uri is that Apache does not fill out several things
 * in the apr_uri_t structure...  unimportant things, like 'hostname', and 'scheme', and 'port'...  so we must
 * implement a trimmed down version of apr_uri_unparse
 */
static char *getCASService(request_rec *r, cas_cfg *c)
{
	char *scheme, *service, *unparsedPath = NULL, *queryString = strchr(r->unparsed_uri, '?');
	int len;
	apr_port_t port = r->connection->local_addr->port;
	apr_byte_t printPort = FALSE;
	
	
	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering getCASService()");
	
	if(queryString != NULL) { 
		len = strlen(r->unparsed_uri) - strlen(queryString);
		unparsedPath = apr_pcalloc(r->pool, len+1);
		strncpy(unparsedPath, r->unparsed_uri, len);
		unparsedPath[len] = '\0';
	} else {
		unparsedPath = r->unparsed_uri;
	}
	
	if(c->CASRootProxiedAs.is_initialized) {
		service = apr_psprintf(r->pool, "%s%s%s%s", escapeString(r, apr_uri_unparse(r->pool, &c->CASRootProxiedAs, 0)), escapeString(r, unparsedPath), (r->args != NULL ? "%3f" : ""), escapeString(r, r->args));
	} else {
		if(isSSL(r) && port != 443)
			printPort = TRUE;
		else if(port != 80)
			printPort = TRUE;
#ifdef APACHE2_0
		scheme = (char *) ap_http_method(r);
#else
		scheme = (char *) ap_http_scheme(r);
#endif
		
		if(printPort == TRUE)
			service = apr_psprintf(r->pool, "%s%%3a%%2f%%2f%s%%3a%u%s%s%s", scheme, r->server->server_hostname, port, escapeString(r, unparsedPath), (r->args != NULL ? "%3f" : ""), escapeString(r, r->args));
		else
			service = apr_psprintf(r->pool, "%s%%3a%%2f%%2f%s%s%s%s", scheme, r->server->server_hostname, escapeString(r, unparsedPath), (r->args != NULL ? "%3f" : ""), escapeString(r, r->args));
		
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "CAS Service '%s'", service);
	}
	return(service);
}


/* utility functions that relate to request handling */
static void redirectRequest(request_rec *r, cas_cfg *c)
{
	char *destination;
	char *service = getCASService(r, c);
	char *loginURL = getCASLoginURL(r, c);
	char *renew = getCASRenew(r);
	char *gateway = getCASGateway(r);
	char *allow = getCASAllow(r);
	char *retry = getCASretry(r);
	char *message = getRealmAsMessage(r);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering redirectRequest()");

	if(loginURL == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Cannot redirect request (no CASLoginURL)");
		return;
	}

	destination = apr_pstrcat(r->pool, loginURL, "?service=", service, renew, gateway, allow, retry, message, NULL);

	apr_table_add(r->headers_out, "Location", destination);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Adding outgoing header: Location: %s", destination);

}

static apr_byte_t removeCASParams(request_rec *r)
{
	char *newArgs, *oldArgs, *p;
	apr_byte_t copy = TRUE;
	apr_byte_t changed = FALSE;
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

	if(r->args == NULL)
		return changed;

	oldArgs = r->args;
	p = newArgs = apr_pcalloc(r->pool, strlen(oldArgs) + 1); /* add 1 for terminating NULL */
	while(*oldArgs != '\0') {
		/* stop copying when a CAS parameter is encountered */
		if(strncmp(oldArgs, "ticket=", 7) == 0) {
			copy = FALSE;
			changed = TRUE;
		}
		if(strncmp(oldArgs, "renew=", 6) == 0) {
			copy = FALSE;
			changed = TRUE;
		}
		if(strncmp(oldArgs, "gateway=", 8) == 0) {
			copy = FALSE;
			changed = TRUE;
		}
		if(copy)
			*p++ = *oldArgs++;
		/* restart copying on a new parameter */
		else if(*oldArgs++ == '&')
			copy = TRUE;
	}

	/* if the last character is a ? or &, strip it */
	if(strlen(newArgs) >= 1 && (*(p-1) == '&' || *(p-1) == '?'))
		p--;
	/* null terminate the string */
	*p = '\0';
	
	if(c->CASDebug && changed == TRUE)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Modified r->args (old '%s', new '%s')", r->args, newArgs);

	if(strlen(newArgs) != 0 && changed == TRUE)
		/* r->args is by definition larger or the same size than newArgs, so strcpy() is safe */
		strcpy(r->args, newArgs);
	else if(strlen(newArgs) == 0)
		r->args = NULL;

	return changed;
}

static char *getCASTicket(request_rec *r)
{
	char *tokenizerCtx, *ticket, *args, *rv = NULL;
	apr_byte_t ticketFound = FALSE;

	if(r->args == NULL || strlen(r->args) == 0)
		return NULL;

	args = apr_pstrndup(r->pool, r->args, strlen(r->args));
	/* tokenize on & to find the 'ticket' parameter */
	ticket = apr_strtok(args, "&", &tokenizerCtx);
	do {
		if(strncmp(ticket, "ticket=", 7) == 0) {
			ticketFound = TRUE;
			/* skip to the meat of the parameter (the value after the '=') */
			ticket += 7; 
			rv = apr_pstrdup(r->pool, ticket);
			break;
		}
		ticket = apr_strtok(NULL, "&", &tokenizerCtx);
		/* no more parameters */
		if(ticket == NULL)
			break;
	} while (ticketFound == FALSE);

	return rv;
}

static char *getCASCookie(request_rec *r, char *cookieName)
{
	char *cookie, *tokenizerCtx, *rv = NULL;
	apr_byte_t cookieFound = FALSE;
	char *cookies = apr_pstrdup(r->pool, (char *) apr_table_get(r->headers_in, "Cookie"));
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);
	
	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Entering getCASCookie (cookie '%s')", cookieName);
	
	if(cookies != NULL) {
		/* tokenize on ; to find the cookie we want */
		cookie = apr_strtok(cookies, ";", &tokenizerCtx);
		do {
			while (cookie != NULL && *cookie == ' ')
				cookie++;
			if(strncmp(cookie, cookieName, strlen(cookieName)) == 0) {
				cookieFound = TRUE;
				/* skip to the meat of the parameter (the value after the '=') */
				cookie += (strlen(cookieName)+1);
				rv = apr_pstrdup(r->pool, cookie);
			}
			cookie = apr_strtok(NULL, ";", &tokenizerCtx);
		/* no more parameters */
		if(cookie == NULL)
			break;
		} while (cookieFound == FALSE);
	}

	return rv;
}

static void setCASCookie(request_rec *r, char *cookieName, char *cookieValue, apr_byte_t secure)
{
	char *headerString, *currentCookies, *pathPrefix = "";
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering setCASCookie()");

	if(c->CASRootProxiedAs.is_initialized)
		pathPrefix = urlEncode(r, c->CASRootProxiedAs.path, " ");

	headerString = apr_psprintf(r->pool, "%s=%s%s;Path=%s%s%s%s%s", cookieName, cookieValue, (secure ? ";Secure" : ""), pathPrefix, getCASScope(r), (c->CASCookieDomain != NULL ? ";Domain=" : ""), (c->CASCookieDomain != NULL ? c->CASCookieDomain : ""), (c->CASCookieHttpOnly != FALSE ? "; HttpOnly" : ""));

	/* use r->err_headers_out so we always print our headers (even on 302 redirect) - headers_out only prints on 2xx responses */
	apr_table_add(r->err_headers_out, "Set-Cookie", headerString);

	/*
	 * There is a potential problem here.  If CASRenew is on and a user requests 'http://example.com/xyz/'
	 * then they are bounced out to the CAS server and they come back with a ticket.  This ticket is validated
	 * and then this function (setCASCookie) is installed.  However, mod_dir will create a subrequest to
	 * point them to some DirectoryIndex value.  mod_auth_cas will see this new request (with no ticket since
	 * we removed it, but it would be invalid anyway since it was already validated at the CAS server)
	 * and redirect the user back to the CAS server (this time appending 'index.html' or something similar
	 * to the request) requiring two logins.  By adding this cookie to the incoming headers, when the
	 * subrequest is sent, they will use their established session.
	 */
	if((currentCookies = (char *) apr_table_get(r->headers_in, "Cookie")) == NULL)
		apr_table_add(r->headers_in, "Cookie", headerString);
	else
		apr_table_set(r->headers_in, "Cookie", (apr_pstrcat(r->pool, headerString, ";", currentCookies, NULL)));
	
	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Adding outgoing header: Set-Cookie: %s", headerString);


	return;
}

/* 
 * The CAS protocol spec 2.1.1 says the URL value MUST be URL-encoded as described in 2.2 of RFC 1738.
 * The rfc1738 array below represents the 'unsafe' characters from that section.  No encoding is performed
 * on 'control characters' (0x00-0x1F) or characters not used in US-ASCII (0x80-0xFF) - is this a problem?
 */
static char *escapeString(request_rec *r, char *str)
{
	char *rfc1738 = "+ <>\"%{}|\\^~[]`;/?:@=&#";
	
	return(urlEncode(r, str, rfc1738));
}

static char *urlEncode(request_rec *r, char *str, char *charsToEncode)
{
	char *rv, *p, *q;
	size_t i, j, size;
	char escaped = FALSE;
	
	if(str == NULL)
		return "";
	
	size = strlen(str) + 1; /* add 1 for terminating NULL */
	
	for(i = 0; i < size; i++) {
		for(j = 0; j < strlen(charsToEncode); j++) {
			if(str[i] == charsToEncode[j]) {
				/* allocate 2 extra bytes for the escape sequence (' ' -> '%20') */
				size += 2;
				break;
			}
		}
	}
	/* allocate new memory to return the encoded URL */
	p = rv = apr_pcalloc(r->pool, size);
	q = str;
	
	do {
		escaped = FALSE;
		for(i = 0; i < strlen(charsToEncode); i++) {
			if(*q == charsToEncode[i]) {
				sprintf(p, "%%%x", charsToEncode[i]);
				p+= 3;
				escaped = TRUE;
				break;
			}
		}
		if(escaped == FALSE) {
			*p++ = *q;
		}
		
		q++;
	} while (*q != '\0');
	*p = '\0';
	
	return(rv);
}

/* functions related to the local cache */
static apr_byte_t readCASCacheFile(request_rec *r, cas_cfg *c, char *name, cas_cache_entry *cache)
{
	apr_off_t begin = 0;
	apr_file_t *f;
	apr_finfo_t fi;
	apr_xml_parser *parser;
	apr_xml_doc *doc;
	apr_xml_elem *e;
	char errbuf[CAS_MAX_ERROR_SIZE];
	char *path;
	const char *val;
	int i;

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering readCASCacheFile()");

	/* first, validate that cookie looks like an MD5 string */
	if(strlen(name) != APR_MD5_DIGESTSIZE*2) {
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Invalid cache cookie length for '%s', (expecting %d, got %d)", name, APR_MD5_DIGESTSIZE*2, (int) strlen(name));
		return FALSE;
	}

	for(i = 0; i < APR_MD5_DIGESTSIZE*2; i++) {
		if((name[i] < 'a' || name[i] > 'f') && (name[i] < '0' || name[i] > '9')) {
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Invalid character in cache cookie '%s' (%c)", name, name[i]);
			return FALSE;
		}
	}

	/* fix MAS-4 JIRA issue */
	if(apr_stat(&fi, c->CASCookiePath, APR_FINFO_TYPE, r->pool) == APR_INCOMPLETE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not find Cookie Path '%s'", c->CASCookiePath);
		return FALSE;
	}

	if(fi.filetype != APR_DIR || c->CASCookiePath[strlen(c->CASCookiePath)-1] != '/') {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Cookie Path '%s' is not a directory or does not end in a trailing '/'!", c->CASCookiePath);
		return FALSE;
	}
	/* end MAS-4 JIRA issue */

	/* open the file if it exists and make sure that the ticket has not expired */
	path = apr_psprintf(r->pool, "%s%s", c->CASCookiePath, name);

	if(apr_file_open(&f, path, APR_FOPEN_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache entry '%s' could not be opened", name);
		return FALSE;
	}

	if(cas_flock(f, LOCK_SH, r)) {
		if(c->CASDebug) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not obtain shared lock on %s", name);
		}
		apr_file_close(f);
		return FALSE;
	}

	/* read the various values we store */
	apr_file_seek(f, APR_SET, &begin);

	rv = apr_xml_parse_file(r->pool, &parser, &doc, f, CAS_MAX_XML_SIZE);
	if(rv != APR_SUCCESS) {
		if(parser == NULL) {
			/*
			 * apr_xml_parse_file can fail early enough that the parser value is left uninitialized.
			 * In this case, we'll use apr_strerror and avoid calling apr_xml_parser_geterror, which
			 * segfaults with a null parser.
			 * patch to resolve this provided by Chris Adams of Yale
			 */
			apr_strerror(rv, errbuf, sizeof(errbuf));
		} else {
			apr_xml_parser_geterror(parser, errbuf, sizeof(errbuf));
		}

		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Error parsing XML content (%s)", errbuf);
		if(cas_flock(f, LOCK_UN, r)) {
			if(c->CASDebug) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not release shared lock on %s", name);
			}
		}
		apr_file_close(f);
		return FALSE;
	}

	e = doc->root->first_child;
	/* XML structure: 
 	 * cacheEntry
	 *	attr
	 *	attr
	 *	...
 	 */

	/* initialize things to sane values */
	cache->user = NULL;
	cache->issued = 0;
	cache->lastactive = 0;
	cache->path = "";
	cache->renewed = FALSE;
	cache->secure = FALSE;
	cache->ticket = NULL;
	cache->authtype = NULL;
	cache->maillist = NULL;
	cache->password = NULL;
	cache->attrs = NULL;

	do {
		if(e == NULL)
			continue;

		/* determine textual content of this element */
		apr_xml_to_text(r->pool, e, APR_XML_X2T_INNER, NULL, NULL, &val, NULL);

		if (apr_strnatcasecmp(e->name, "user") == 0)
			cache->user = apr_pstrndup(r->pool, val, strlen(val));
		else if (apr_strnatcasecmp(e->name, "issued") == 0) {
			if(sscanf(val, "%" APR_TIME_T_FMT, &(cache->issued)) != 1) {
				if(cas_flock(f, LOCK_UN, r)) {
					if(c->CASDebug) {
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not release shared lock on %s", name);
					}
				}
				apr_file_close(f);
				return FALSE;
			}
		} else if (apr_strnatcasecmp(e->name, "lastactive") == 0) {
			if(sscanf(val, "%" APR_TIME_T_FMT, &(cache->lastactive)) != 1) {
				if(cas_flock(f, LOCK_UN, r)) {
					if(c->CASDebug) {
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not release shared lock on %s", name);
					}
				}
				apr_file_close(f);
				return FALSE;
			}
		} else if (apr_strnatcasecmp(e->name, "path") == 0)
			cache->path = apr_pstrndup(r->pool, val, strlen(val));
		else if (apr_strnatcasecmp(e->name, "renewed") == 0)
			cache->renewed = TRUE;
		else if (apr_strnatcasecmp(e->name, "secure") == 0)
			cache->secure = TRUE;
		else if (apr_strnatcasecmp(e->name, "ticket") == 0)
			cache->ticket = apr_pstrndup(r->pool, val, strlen(val));
		else if (apr_strnatcasecmp(e->name, "authtype") == 0)
			cache->authtype = apr_pstrndup(r->pool, val, strlen(val));
		else if (apr_strnatcasecmp(e->name, "maillist") == 0)
			cache->maillist = apr_pstrndup(r->pool, val, strlen(val));
		else if (apr_strnatcasecmp(e->name, "password") == 0) {
			char * decoded_line = apr_palloc(r->pool, apr_base64_decode_len(val) + 1);
			int length = apr_base64_decode(decoded_line, val);
			/* Null-terminate the string. */
			decoded_line[length] = '\0';
			
			cache->password = apr_pstrndup(r->pool, decoded_line, length);
		}
		else if (apr_strnatcasecmp(e->name, "attributes") == 0) {
			cas_attr_builder *builder = cas_attr_builder_new(r->pool, &(cache->attrs));
			apr_xml_elem *attrs;
			apr_xml_elem *v;
			const char *attr_value;
			const char *attr_name;

			for (attrs = e->first_child; attrs != NULL; attrs = attrs->next) {
				attr_name = attrs->attr->value;
				for (v = attrs->first_child; v != NULL; v = v->next) {
					apr_xml_to_text(r->pool, v, APR_XML_X2T_INNER,
							NULL, NULL, &attr_value, NULL);
					cas_attr_builder_add(builder, attr_name, attr_value);
				}
			}
		}
		else
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Unknown cookie attribute '%s'", e->name);
		e = e->next;
	} while (e != NULL);

	if(cas_flock(f, LOCK_UN, r)) {
		if(c->CASDebug) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not release shared lock on %s", name);
		}
	}
	apr_file_close(f);
	return TRUE;
}

static void CASCleanCache(request_rec *r, cas_cfg *c)
{
	apr_time_t lastClean;
	apr_off_t begin = 0;
	char *path;
	apr_file_t *metaFile, *cacheFile;
	char line[64];
	apr_status_t i;
	cas_cache_entry cache;
	apr_dir_t *cacheDir;
	apr_finfo_t fi;

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering CASCleanCache()");

	path = apr_psprintf(r->pool, "%s.metadata", c->CASCookiePath);


	if(apr_file_open(&metaFile, path, APR_FOPEN_READ|APR_FOPEN_WRITE, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool) != APR_SUCCESS) {
		/* file does not exist or cannot be opened - try and create it */
		if((i = apr_file_open(&metaFile, path, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), (APR_FPROT_UREAD|APR_FPROT_UWRITE), r->pool)) != APR_SUCCESS) {
			apr_strerror(i, line, sizeof(line));
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MOD_AUTH_CAS: Could not create cache metadata file '%s': %s", path, line);
			return;
		}
	}

	if(cas_flock(metaFile, LOCK_EX, r)) {
		if(c->CASDebug) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not obtain exclusive lock on %s", path);
		}
		apr_file_close(metaFile);
		return;
	}
	apr_file_seek(metaFile, APR_SET, &begin);

	/* if the file was not created on this method invocation (APR_FOPEN_READ is not used above during creation) see if it is time to clean the cache */
	if((apr_file_flags_get(metaFile) & APR_FOPEN_READ) != 0) {
		apr_file_gets(line, sizeof(line), metaFile);
		if(sscanf(line, "%" APR_TIME_T_FMT, &lastClean) != 1) { /* corrupt file */
			if(cas_flock(metaFile, LOCK_UN, r)) {
				if(c->CASDebug) {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not release exclusive lock on %s", path);
				}
			}
			apr_file_close(metaFile);
			apr_file_remove(path, r->pool);
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache metadata file is corrupt");
			return;
		}
		if(lastClean > (apr_time_now()-(c->CASCacheCleanInterval*((apr_time_t) APR_USEC_PER_SEC)))) { /* not enough time has elapsed */
			/* release the locks and file descriptors that we no longer need */
			if(cas_flock(metaFile, LOCK_UN, r)) {
				if(c->CASDebug) {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not release exclusive lock on %s", path);
				}
			}
			apr_file_close(metaFile);
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Insufficient time elapsed since last cache clean");
			return;
		}

		apr_file_seek(metaFile, APR_SET, &begin);
		apr_file_trunc(metaFile, begin);
	}

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Beginning cache clean");

	apr_file_printf(metaFile, "%" APR_TIME_T_FMT "\n", apr_time_now());
	if(cas_flock(metaFile, LOCK_UN, r)) {
		if(c->CASDebug) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not release exclusive lock on %s", path);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Continuing with cache clean...");
		}
	}
	apr_file_close(metaFile);

	/* read all the files in the directory */
	if(apr_dir_open(&cacheDir, c->CASCookiePath, r->pool) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MOD_AUTH_CAS: Error opening cache directory '%s' for cleaning", c->CASCookiePath);
	}

	do {
		i = apr_dir_read(&fi, APR_FINFO_NAME, cacheDir);
		if(i == APR_SUCCESS) {
			if(fi.name[0] == '.') /* skip hidden files and parent directories */
				continue;
			path = apr_psprintf(r->pool, "%s%s", c->CASCookiePath, fi.name);
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Processing cache file '%s'", fi.name);

			if(apr_file_open(&cacheFile, path, APR_FOPEN_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Unable to clean cache entry '%s'", path);
				continue;
			}
			if(readCASCacheFile(r, c, (char *) fi.name, &cache) == TRUE) {
				if((c->CASTimeout > 0 && (cache.issued < (apr_time_now()-(c->CASTimeout*((apr_time_t) APR_USEC_PER_SEC))))) || cache.lastactive < (apr_time_now()-(c->CASIdleTimeout*((apr_time_t) APR_USEC_PER_SEC)))) {
					/* delete this file since it is no longer valid */
					apr_file_close(cacheFile);
					deleteCASCacheFile(r, (char *) fi.name);
					if(c->CASDebug)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Removing expired cache entry '%s'", fi.name);
				}
			} else {
				if(c->CASDebug)
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Removing corrupt cache entry '%s'", fi.name);
				/* corrupt file */
				apr_file_close(cacheFile);
				deleteCASCacheFile(r, (char *) fi.name);
			}
		}
	} while (i == APR_SUCCESS);
	apr_dir_close(cacheDir);

}

static apr_byte_t writeCASCacheEntry(request_rec *r, char *name, cas_cache_entry *cache, apr_byte_t exists)
{
	char *path;
	apr_file_t *f;
	apr_off_t begin = 0;
	int cnt = 0;
	apr_status_t i = APR_EGENERAL;
	apr_byte_t lock = FALSE;
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering writeCASCacheEntry()");

	path = apr_psprintf(r->pool, "%s%s", c->CASCookiePath, name);

	if(exists == FALSE) {
		if((i = apr_file_open(&f, path, APR_FOPEN_CREATE|APR_FOPEN_WRITE|APR_EXCL, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Cookie file '%s' could not be created: %s", path, apr_strerror(i, name, strlen(name)));
			return FALSE;
		}
	} else {
		for(cnt = 0; ; cnt++) {
			/* gracefully handle broken file system permissions by trying 3 times to create the file, otherwise failing */
			if(cnt >= 3) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Cookie file '%s' could not be opened: %s", path, apr_strerror(i, name, strlen(name)));
				return FALSE;
			}
			if(apr_file_open(&f, path, APR_FOPEN_READ|APR_FOPEN_WRITE, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool) == APR_SUCCESS)
				break;
			else
				apr_sleep(1000);
		}

		/* update the file with a new idle time if a write lock can be obtained */
		if(cas_flock(f, LOCK_EX, r)) {
			if(c->CASDebug) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not obtain exclusive lock on %s", name);
			}
			apr_file_close(f);
			return FALSE;
		} else
			lock = TRUE;
		apr_file_seek(f, APR_SET, &begin);
		apr_file_trunc(f, begin);
	}

	/* this is ultra-ghetto, but the APR really doesn't provide any facilities for easy DOM-style XML creation. */
	apr_file_printf(f, "<cacheEntry xmlns=\"http://uconn.edu/cas/mod_auth_cas\">\n");
	apr_file_printf(f, "<user>%s</user>\n", apr_xml_quote_string(r->pool, cache->user, TRUE));
	apr_file_printf(f, "<issued>%" APR_TIME_T_FMT "</issued>\n", cache->issued);
	apr_file_printf(f, "<lastactive>%" APR_TIME_T_FMT "</lastactive>\n", cache->lastactive);
	apr_file_printf(f, "<path>%s</path>\n", apr_xml_quote_string(r->pool, cache->path, TRUE));
	apr_file_printf(f, "<ticket>%s</ticket>\n", apr_xml_quote_string(r->pool, cache->ticket, TRUE));
	if (cache->authtype!=NULL) apr_file_printf(f, "<authtype>%s</authtype>\n", apr_xml_quote_string(r->pool, cache->authtype, TRUE));
	if (cache->maillist!=NULL) apr_file_printf(f, "<maillist>%s</maillist>\n", apr_xml_quote_string(r->pool, cache->maillist, TRUE));
	if (cache->password!=NULL && cache->authtype!=NULL && !strcasecmp(cache->authtype,"apache")) {
		char * encoded_line = apr_palloc(r->pool, apr_base64_encode_len(strlen(cache->password)));
		int length = apr_base64_encode(encoded_line, cache->password, strlen(cache->password));
		apr_file_printf(f, "<password>%s</password>\n", apr_xml_quote_string(r->pool, encoded_line, TRUE));
	}
	if(cache->attrs != NULL) {
		cas_saml_attr *a = cache->attrs;
		apr_file_printf(f, "<attributes>\n");
		while(a != NULL) {
			cas_saml_attr_val *av = a->values;
			apr_file_printf(f, "  <attribute name=\"%s\">\n", apr_xml_quote_string(r->pool, a->attr, TRUE));
			while(av != NULL) {
				apr_file_printf(f, "	<value>%s</value>\n", apr_xml_quote_string(r->pool, av->value, TRUE));
				av = av->next;
			}
			apr_file_printf(f, "  </attribute>\n");
			a = a->next;
		}
		apr_file_printf(f, "</attributes>\n");
	}
	if(cache->renewed != FALSE)
		apr_file_printf(f, "<renewed />\n");
	if(cache->secure != FALSE)
		apr_file_printf(f, "<secure />\n");
	apr_file_printf(f, "</cacheEntry>\n");

	if(lock != FALSE) {
		if(cas_flock(f, LOCK_UN, r)) {
			if(c->CASDebug) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: Could not release exclusive lock on %s", name);
			}
		}
	}

	apr_file_close(f);

	return TRUE;
}

static char *createBasicCASCacheName(request_rec *r) {
	/*
	 * Normally the cache entries are stored in a file whose name is a random string. That random
	 * string is stored in a cookie so we can find the cache entry again.
	 *
	 * When using the Basic authentication option, we may not be talking to a browser, so there may
	 * not be an ability to use cookies. In this case, we need to use a name for the cache file that
	 * we can reproduce from information available from the Basic authentication. This includes:
	 *		user name
	 *		user password
	 *		realm
	 *		ip address
	 *		path to page
	 */
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211
	char *buf = apr_pstrcat(r->pool, r->connection->client_ip, r->user, d->password, r->ap_auth_type, getCASPath(r), NULL);
#else
	char *buf = apr_pstrcat(r->pool, r->connection->remote_ip, r->user, d->password, r->ap_auth_type, getCASPath(r), NULL);
#endif
	char *cacheName = (char *) ap_md5_binary(r->pool, (unsigned char *) buf, strlen(buf));

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Basic cache name '%s'", cacheName);

	return cacheName;
	
}

static char *createCASCookie(request_rec *r, char *user, cas_saml_attr *attrs, char *ticket, char *authtype, char *maillist)
{
	char *path, *buf, *rv;
	apr_file_t *f;
	apr_byte_t createSuccess;
	cas_cache_entry e;
	int i;
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
	buf = apr_pcalloc(r->pool, c->CASCookieEntropy);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering createCASCookie(,%s,%s,%s,%s,%s)",user,ticket,authtype,maillist,d->password);

	CASCleanCache(r, c);

	e.user = user;
	e.issued = apr_time_now();
	e.lastactive = apr_time_now();
	e.path = getCASPath(r);
	e.renewed = (d->CASRenew == NULL ? 0 : 1);
	e.secure = (isSSL(r) == TRUE ? 1 : 0);
	e.ticket = ticket;
	e.authtype = authtype;
	e.maillist = maillist;
	e.password = d->password;
	e.attrs = attrs;
	
	if (r->ap_auth_type!=NULL && 0==apr_strnatcasecmp((const char *) r->ap_auth_type, "basic")) {
		rv = createBasicCASCacheName(r);
		writeCASCacheEntry(r, rv, &e, FALSE);
	} else {
		/* this may block since this reads from /dev/random - however, it hasn't been a problem in testing */
		apr_generate_random_bytes((unsigned char *) buf, c->CASCookieEntropy);
		rv = (char *) ap_md5_binary(r->pool, (unsigned char *) buf, c->CASCookieEntropy);
	}
	/* 
	 * Associate this text with user for lookups later.  By using files instead of 
	 * shared memory the advantage of NFS shares in a clustered environment or a 
	 * memory based file systems can be used at the expense of potentially some performance
	 */
	if(writeCASCacheEntry(r, rv, &e, FALSE) == FALSE)
		return NULL;
	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' created for user '%s'", rv, user);

	buf = (char *) ap_md5_binary(r->pool, (const unsigned char *) ticket, (int) strlen(ticket));
	path = apr_psprintf(r->pool, "%s.%s", c->CASCookiePath, buf);

	if((i = apr_file_open(&f, path, APR_FOPEN_CREATE|APR_FOPEN_WRITE|APR_EXCL, APR_FPROT_UREAD|APR_FPROT_UWRITE, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Service Ticket to Cookie map file '%s' could not be created: %s", path, apr_strerror(i, buf, strlen(buf)));
		return FALSE;
	} else {
		apr_file_printf(f, "%s", rv);
		apr_file_close(f);
	}
	
	return(apr_pstrdup(r->pool, rv));
}

static void expireCASST(request_rec *r, char *ticketname)
{
	char *ticket, *path;
	char line[APR_MD5_DIGESTSIZE*2+1];
	apr_file_t *f;
	apr_size_t bytes = APR_MD5_DIGESTSIZE*2;
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering expireCASST()");

	ticket = (char *) ap_md5_binary(r->pool, (unsigned char *) ticketname, (int) strlen(ticketname));
	line[APR_MD5_DIGESTSIZE*2] = '\0';

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Expiring service ticket '%s' (%s)", ticketname, ticket);

	path = apr_psprintf(r->pool, "%s.%s", c->CASCookiePath, ticket);

	if(apr_file_open(&f, path, APR_FOPEN_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Service Ticket mapping to Cache entry '%s' could not be opened (ticket %s - expired already?)", path, ticketname);
		return;
	}
	
	if(apr_file_read(f, &line, &bytes) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Service Ticket mapping to Cache entry '%s' could not be read (ticket %s)", path, ticketname);
		return;
	}
	
	if(bytes != APR_MD5_DIGESTSIZE*2) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Service Ticket mapping to Cache entry '%s' incomplete (read %" APR_SIZE_T_FMT ", expected %d, ticket %s)", path, bytes, APR_MD5_DIGESTSIZE*2, ticketname);
		return;
	}

	apr_file_close(f);

	deleteCASCacheFile(r, line);
}
#ifdef BROKEN
static void CASSAMLLogout(request_rec *r, char *body)
{
	apr_xml_doc *doc;
	apr_xml_elem *node;
	char *line;
	apr_xml_parser *parser = apr_xml_parser_create(r->pool);
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

	if(body != NULL && strncmp(body, "logoutRequest=", 14) == 0) {
		body += 14;
		line = (char *) body;

		/* convert + to ' ' or else the XML won't parse right */
		do { 
			if(*line == '+')
				*line = ' ';
			line++;
		} while (*line != '\0');

		ap_unescape_url((char *) body);

		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "SAML Logout Request: %s", body);

		/* parse the XML response */
		if(apr_xml_parser_feed(parser, body, strlen(body)) != APR_SUCCESS) {
			line = apr_pcalloc(r->pool, 512);
			apr_xml_parser_geterror(parser, line, 512);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: error parsing SAML logoutRequest: %s (incomplete SAML body?)", line);
			return;
		}
		/* retrieve a DOM object */
		if(apr_xml_parser_done(parser, &doc) != APR_SUCCESS) {
			line = apr_pcalloc(r->pool, 512);
			apr_xml_parser_geterror(parser, line, 512);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: error retrieving XML document for SAML logoutRequest: %s", line);
			return;
		}

		node = doc->root->first_child;
		while(node != NULL) {
			if(apr_strnatcmp(node->name, "SessionIndex") == 0 && node->first_cdata.first != NULL) {
				expireCASST(r, (char *) node->first_cdata.first->text);
				return;
			}
			node = node->next;
		}
	}

	return;
}
#endif
static void deleteCASCacheFile(request_rec *r, char *cookieName)
{
	char *path, *ticket;
	cas_cache_entry e;
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering deleteCASCacheFile()");

	/* we need this to get the ticket */
	readCASCacheFile(r, c, cookieName, &e);

	/* delete their cache entry */
	path = apr_psprintf(r->pool, "%s%s", c->CASCookiePath, cookieName);
	apr_file_remove(path, r->pool);

	/* delete the ticket -> cache entry mapping */
	ticket = (char *) ap_md5_binary(r->pool, (unsigned char *) e.ticket, strlen(e.ticket));
	path = apr_psprintf(r->pool, "%s.%s", c->CASCookiePath, ticket);
	apr_file_remove(path, r->pool);

	return;
}

/* functions related to validation of tickets/cache entries */
static apr_byte_t isValidCASTicket(request_rec *r, cas_cfg *c, char *ticket, char **user, cas_saml_attr **attrs, char **authtype, char **maillist, char **password)
{
	char *line;
	apr_xml_doc *doc;
	apr_xml_elem *node;
	apr_xml_attr *attr;
	apr_xml_parser *parser = apr_xml_parser_create(r->pool);
	const char *response = getResponseFromServer(r, c, ticket);
	
	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering isValidCASTicket()");

	if(response == NULL)
		return FALSE;

	response = strstr((char *) response, "\r\n\r\n");

	if(response == NULL)
		return FALSE;

	/* skip the \r\n\r\n after the HTTP headers */
	response += 4;

	if(c->CASVersion == 1) {
		do {
			line = ap_getword(r->pool, &response, '\n');
			/* premature response end */
			if(strlen(line) == 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: premature end of CASv1 response (yes/no not present)");
				return FALSE;
			}

		} while (apr_strnatcmp(line, "no") != 0 && apr_strnatcmp(line, "yes") != 0);
		
		if(apr_strnatcmp(line, "no") == 0) {
			return FALSE;
		}

		line = ap_getword(r->pool, &response, '\n');
		/* premature response end */
		if(line == NULL || strlen(line) == 0) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: premature end of CASv1 response (username not present)");
			return FALSE;
		}

		*user = apr_pstrndup(r->pool, line, strlen(line));
		if (strstr(*user,"@alumni.sfu.ca")) *authtype = "alumni";
		else *authtype = "sfu";
		return TRUE;
	} else if(c->CASVersion == 2) {
		/* parse the XML response */
		if(apr_xml_parser_feed(parser, response, strlen(response)) != APR_SUCCESS) {
			line = apr_pcalloc(r->pool, 512);
			apr_xml_parser_geterror(parser, line, 512);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: error parsing CASv2 response: %s", line);
			return FALSE;
		}
		/* retrieve a DOM object */
		if(apr_xml_parser_done(parser, &doc) != APR_SUCCESS) {
			line = apr_pcalloc(r->pool, 512);
			apr_xml_parser_geterror(parser, line, 512);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: error retrieving XML document for CASv2 response: %s", line);
			return FALSE;
		}
		/* XML tree:
		 * ServiceResponse
		 *  ->authenticationSuccess
		 *      ->user
		 *		->authtype (SFU only)
		 *		->maillist (SFU only)
		 *		->password (SFU only)
		 *      ->proxyGrantingTicket
		 *  ->authenticationFailure (code)
		 */
		node = doc->root->first_child;
		if(apr_strnatcmp(node->name, "authenticationSuccess") == 0) {
			int gotUser = 0;
			for (node = node->first_child; node != NULL; node=node->next) {
				line = (char *) (node->first_cdata.first->text);
				if (apr_strnatcmp(node->name, "user") == 0) {
					*user = apr_pstrndup(r->pool, line, strlen(line));
					gotUser = 1;
					continue;
				} else if (apr_strnatcmp(node->name, "authtype") == 0) {
					*authtype = apr_pstrndup(r->pool, line, strlen(line));
					continue;
				} else if (apr_strnatcmp(node->name, "maillist") == 0) {
					*maillist = apr_pstrndup(r->pool, line, strlen(line));
					continue;
				} else if (apr_strnatcmp(node->name, "password") == 0) {
					apr_text *t = node->first_cdata.first;
					*password = apr_pstrndup(r->pool, line, strlen(line));
					while ((t = t->next)) {
						*password = apr_pstrcat(r->pool, *password, t->text, NULL);
					}
					continue;
				}
			}
			
			// Check username and password against that in .htpasswd
			if ((authtype != NULL) && (*authtype != NULL) && !strcasecmp(*authtype,"apache")) {
				cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
				ap_configfile_t *f;
				char l[CAS_MAX_RESPONSE_SIZE+1];
			
				// Check that username and password are not null. Return false if null.
				if (!gotUser) return FALSE;
				if (*password==NULL) return FALSE;
				
				if(c->CASDebug)
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "isValidCASTicket: Trying to open htpasswd file '%s'", d->pwfile==NULL?"(NULL)":d->pwfile);
				if (APR_SUCCESS == ap_pcfg_openfile(&f, r->pool, d->pwfile)) {
					if (c->CASDebug)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "isValidCASTicket: Successfully opened '%s'", d->pwfile);
			
					while (!(ap_cfg_getline(l, CAS_MAX_RESPONSE_SIZE, f))) {
						if ((l[0] == '#') || (l[0] == 0)) continue; // ignore comment or blank lines
						if (l[0] == '+') continue; // an SFU line
						if (!strncmp(l, *user, strlen(*user)) && l[strlen(*user)]==':') {
							if (APR_SUCCESS == apr_password_validate(*password, l+strlen(*user)+1)) {
								if (c->CASDebug)
									ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "isValidCASTicket: Successfully validated password for '%s'", *user);
								return TRUE;
							}
						}
					}
				} else {
					if (c->CASDebug)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "isValidCASTicket: Unable to opened '%s'", d->pwfile);
				}
				return FALSE;
			}
			
			if (gotUser) return TRUE;
		} else if (apr_strnatcmp(node->name, "authenticationFailure") == 0) {
			attr = node->attr;
			while(attr != NULL && apr_strnatcmp(attr->name, "code") != 0)
				attr = attr->next;

			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: %s", (attr == NULL ? "Unknown Error" : attr->value));

			return FALSE;
		}
	}
	return FALSE;
}

static apr_byte_t isValidCASCookie(request_rec *r, cas_cfg *c, char *cookie, char **user, cas_saml_attr **attrs, char **authtype, char **maillist, char **password)
{
	char *path;
	cas_cache_entry cache;
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering isValidCASCookie()");

	/* corrupt or invalid file */
	if(readCASCacheFile(r, c, cookie, &cache) != TRUE) {
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' is corrupt or invalid", cookie);
		return FALSE;
	}

	path = apr_psprintf(r->pool, "%s%s", c->CASCookiePath, cookie);
	if (c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie path '%s'", path);

	/* 
	 * mitigate session hijacking by not allowing cookies transmitted in the clear to be submitted
	 * for HTTPS URLs and by voiding HTTPS cookies sent in the clear
	 */
	if( (isSSL(r) == TRUE && cache.secure == FALSE) || (isSSL(r) == FALSE && cache.secure == TRUE) ) {
		/* delete this file since it is no longer valid */
		deleteCASCacheFile(r, cookie);
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' not transmitted via proper HTTP(S) channel, expiring", cookie);
		CASCleanCache(r, c);
		return FALSE;
	}

	if(cache.issued < (apr_time_now()-(c->CASTimeout*((apr_time_t) APR_USEC_PER_SEC))) || cache.lastactive < (apr_time_now()-(c->CASIdleTimeout*((apr_time_t) APR_USEC_PER_SEC)))) {
		/* delete this file since it is no longer valid */
		deleteCASCacheFile(r, cookie);
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' is expired, deleting", cookie);
		CASCleanCache(r, c);
		return FALSE;
	}

	/* see if this cookie contained 'renewed' credentials if this directory requires it */
	if(cache.renewed == FALSE && d->CASRenew != NULL) {
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' does not contain renewed credentials", cookie);
		return FALSE;
	} else if(d->CASRenew != NULL && cache.renewed == TRUE) {
		/* make sure the paths match */
		if(strncasecmp(cache.path, getCASScope(r), strlen(getCASScope(r))) != 0) {
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cookie '%s' does not contain renewed credentials for scope '%s' (path '%s')", cookie, getCASScope(r), getCASPath(r));
			return FALSE;
		}
	}

	/* set the user */
	*user = apr_pstrndup(r->pool, cache.user, strlen(cache.user));
	if (cache.authtype!=NULL)
		*authtype = apr_pstrndup(r->pool, cache.authtype, strlen(cache.authtype));
	if (cache.maillist!=NULL)
		*maillist = apr_pstrndup(r->pool, cache.maillist, strlen(cache.maillist));
	if (cache.password!=NULL)
		*password = apr_pstrndup(r->pool, cache.password, strlen(cache.password));


	cache.lastactive = apr_time_now();
	if(writeCASCacheEntry(r, cookie, &cache, TRUE) == FALSE && c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Could not update cache entry for '%s'", cookie);

	return TRUE;
}


/* SSL specific functions - these should be replaced by the APR-1.3 SSL functions when they are available */
/* Credit to Shawn Bayern for the basis of most of this SSL related code */
static apr_byte_t check_cert_cn(request_rec *r, cas_cfg *c, SSL_CTX *ctx, X509 *certificate, char *cn)
{
	char buf[512];
	char *domain = cn;
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);
	X509_STORE_CTX *xctx = X509_STORE_CTX_new();

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering check_cert_cn()");
	/* specify that 'certificate' (what was presented by the other side) is what we want to verify against 'store' */
	X509_STORE_CTX_init(xctx, store, certificate, sk_X509_new_null());

	/* this may be redundant, since we require peer verification to perform the handshake */
	if(X509_verify_cert(xctx) == 0)
		return FALSE;

	X509_NAME_get_text_by_NID(X509_get_subject_name(certificate), NID_commonName, buf, sizeof(buf) - 1);
	/* don't match because of truncation - this will require a hostname > 512 characters, though */
	if(strlen(cn) >= sizeof(buf) - 1)
		return FALSE;

	/* patch submitted by Earl Fogel for MAS-5 */
	if(buf[0] == '*' && c->CASAllowWildcardCert != FALSE) {
		do {
			domain = strchr(domain + (domain[0] == '.' ? 1 : 0), '.');
			if(domain != NULL && apr_strnatcasecmp(buf+1, domain) == 0)
				return TRUE;
		} while (domain != NULL);
	} else {
		if(apr_strnatcasecmp(buf, cn) == 0)
			return TRUE;
	}
	
	return FALSE;
}

static void CASCleanupSocket(socket_t s, SSL *ssl, SSL_CTX *ctx)
{
	if(s != INVALID_SOCKET)
#ifdef WIN32
		closesocket(s);
#else
		close(s);
#endif

	if(ssl != NULL)
		SSL_free(ssl);

	if(ctx != NULL)
		SSL_CTX_free(ctx);

#ifdef WIN32
	WSACleanup();
#endif
	return;
}

/* also inspired by some code from Shawn Bayern */
static char *getResponseFromServer (request_rec *r, cas_cfg *c, char *ticket)
{
	char *validateRequest, validateResponse[CAS_MAX_RESPONSE_SIZE];
	apr_finfo_t f;
	int i, bytesIn;
	socket_t s = INVALID_SOCKET;

	SSL_METHOD *m;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	struct sockaddr_in sa;
	struct hostent *server = gethostbyname(c->CASValidateURL.hostname);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering getResponseFromServer()");
#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: cannot initialize winsock2: (%d)", WSAGetLastError());
		return NULL;
	}
#endif

	if(server == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: gethostbyname() failed for %s", c->CASValidateURL.hostname);
		return NULL;
	}

	/* establish a TCP connection with the remote server */
	s = socket(AF_INET, SOCK_STREAM, 0);
	if(s == INVALID_SOCKET) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: socket() failed for %s", c->CASValidateURL.hostname);
		// no need to close(s) here since it was never successfully created
		CASCleanupSocket(s, ssl, ctx);
		return (NULL);
	}
	
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(c->CASValidateURL.port);
	memcpy(&(sa.sin_addr.s_addr), (server->h_addr_list[0]), sizeof(sa.sin_addr.s_addr));

	if(connect(s, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: connect() failed to %s:%d", c->CASValidateURL.hostname, ntohs(sa.sin_port));
		CASCleanupSocket(s, ssl, ctx);
		return (NULL);
	}
	
	/* assign the created connection to an SSL object */
	SSL_library_init();
	SSL_load_error_strings();
	m = SSLv23_method();
	ctx = SSL_CTX_new(m);

	if(c->CASValidateServer != FALSE) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		if(apr_stat(&f, c->CASCertificatePath, APR_FINFO_TYPE, r->pool) == APR_INCOMPLETE) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not load CA certificate: %s", c->CASCertificatePath);
			CASCleanupSocket(s, ssl, ctx);
			return (NULL);
		}

		if(f.filetype == APR_DIR) {
			if(!(SSL_CTX_load_verify_locations(ctx, 0, c->CASCertificatePath))) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not load CA certificate path: %s", c->CASCertificatePath);
				CASCleanupSocket(s, ssl, ctx);
				return (NULL);
			}
		} else if (f.filetype == APR_REG) {
			if(!(SSL_CTX_load_verify_locations(ctx, c->CASCertificatePath, 0))) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not load CA certificate file: %s", c->CASCertificatePath);
				CASCleanupSocket(s, ssl, ctx);
				return (NULL);
			}
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not process Certificate Authority: %s", c->CASCertificatePath);
			CASCleanupSocket(s, ssl, ctx);
			return (NULL);
		}

		SSL_CTX_set_verify_depth(ctx, c->CASValidateDepth);
	}

	ssl = SSL_new(ctx);

	if(ssl == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not create an SSL connection to %s", c->CASValidateURL.hostname);
		CASCleanupSocket(s, ssl, ctx);
		return (NULL);
	}

	if(SSL_set_fd(ssl, s) == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not bind SSL connection to socket for %s", c->CASValidateURL.hostname);
		CASCleanupSocket(s, ssl, ctx);
		return (NULL);
	}

	if(SSL_connect(ssl) <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not perform SSL handshake with %s (check CASCertificatePath)", c->CASValidateURL.hostname);
		CASCleanupSocket(s, ssl, ctx);
		return (NULL);
	}

	/* validate the server certificate if we require it, first by verifying the CA signature, then by verifying the CN of the certificate to the hostname */
	if(c->CASValidateServer != FALSE) {
		/* SSL_get_verify_result() will return X509_V_OK if the server did not present a certificate, so we must make sure they do present one */
		if(SSL_get_verify_result(ssl) != X509_V_OK || SSL_get_peer_certificate(ssl) == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Certificate not presented or not signed by CA (from %s)", c->CASValidateURL.hostname);
			CASCleanupSocket(s, ssl, ctx);
			return (NULL);
		} else if(check_cert_cn(r, c, ctx, SSL_get_peer_certificate(ssl), c->CASValidateURL.hostname) == FALSE) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Certificate CN does not match %s", c->CASValidateURL.hostname);
			CASCleanupSocket(s, ssl, ctx);
			return (NULL);
		}
	}

	/* without Connection: close the HTTP/1.1 protocol defaults to trying to keep the connection alive.  this introduces ~15 second lag when receiving a response */
	/* MAS-14 reverts this to HTTP/1.0 because the code that retrieves the ticket validation response can not handle transfer chunked encoding.  this will be solved
	 * at a later date when migrating to libcurl/some other HTTP library to perform ticket validation.  It also removes the Connection: close header as the default
	 * behavior for HTTP/1.0 is Connection: close
	 */
	validateRequest = apr_psprintf(r->pool, "GET %s?service=%s%s&ticket=%s%s HTTP/1.0\nHost: %s\n\n", getCASValidateURL(r, c), getCASService(r, c), getCASAllow(r), ticket, getCASRenew(r), c->CASValidateURL.hostname);
	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Validation request: %s", validateRequest);
	/* send our validation request */
	if(SSL_write(ssl, validateRequest, (int) strlen(validateRequest)) != strlen(validateRequest)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: unable to write CAS validate request to %s%s", c->CASValidateURL.hostname, getCASValidateURL(r, c));
		CASCleanupSocket(s, ssl, ctx);
		return (NULL);
	}
	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Request successfully transmitted");

	/* read the response until there is no more */
	i = 0;
	do {
		bytesIn = SSL_read(ssl, validateResponse + i, (sizeof(validateResponse)-i-1));
		i += bytesIn;
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Received %d bytes of response", bytesIn);
	} while (bytesIn > 0 && i < sizeof(validateResponse));

	validateResponse[i] = '\0';

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Validation response: %s", validateResponse);

	if(bytesIn != 0 || i >= sizeof(validateResponse) - 1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: oversized response received from %s%s", c->CASValidateURL.hostname, getCASValidateURL(r, c));
		CASCleanupSocket(s, ssl, ctx);
		return (NULL);
	}
	
	CASCleanupSocket(s, ssl, ctx);

	return (apr_pstrndup(r->pool, validateResponse, strlen(validateResponse)));
}

//
// When using "Basic" authentication, we are passed an ID and password by the
// application (eg, WebDAV) and so we need to authenticate that with CAS.
// We will use the CAS RESTful interface to do that.
//
// If we are not passed a TGT, then we will call the /tickets REST interface
// passing the ID/password, and get back a TGT (which we will return). 
//
// If we are passed a TGT, then we will call the /tickets/TGT interface
// and get back a ST, which we will return.
//
static char *CAS_tickets(request_rec *r, cas_cfg *c, cas_dir_cfg *d, char *TGT) {
	char *loginRequest, loginResponse[CAS_MAX_RESPONSE_SIZE];
	SSL_METHOD *m;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	struct sockaddr_in sa;
	char *ticketsURL = getCASTicketsURL(r, c);
	struct hostent *server = gethostbyname(c->CASTicketsURL.hostname);
	socket_t s = INVALID_SOCKET;
	apr_finfo_t f;
	int i, bytesIn;
	char *ticketStart;
	
#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0){
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: cannot initialize winsock2: (%d)", WSAGetLastError());
		return NULL;
	}
#endif
	
	if(server == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: gethostbyname() failed for %s", c->CASTicketsURL.hostname);
		return NULL;
	}

	/* establish a TCP connection with the remote server */
	s = socket(AF_INET, SOCK_STREAM, 0);
	if(s == INVALID_SOCKET) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: socket() failed for %s", c->CASTicketsURL.hostname);
		// no need to close(s) here since it was never successfully created
		CASCleanupSocket(s, ssl, ctx);
		return NULL;
	}
	
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(c->CASTicketsURL.port);
	memcpy(&(sa.sin_addr.s_addr), (server->h_addr_list[0]), sizeof(sa.sin_addr.s_addr));
	
	if(connect(s, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: connect() failed to %s:%d", c->CASTicketsURL.hostname, ntohs(sa.sin_port));
		CASCleanupSocket(s, ssl, ctx);
		return NULL;
	}
	
	/* assign the created connection to an SSL object */
	SSL_library_init();
	SSL_load_error_strings();
	m = SSLv23_method();
	ctx = SSL_CTX_new(m);
	
	if(c->CASValidateServer != FALSE) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		
		if(apr_stat(&f, c->CASCertificatePath, APR_FINFO_TYPE, r->pool) == APR_INCOMPLETE) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not load CA certificate: %s", c->CASCertificatePath);
			CASCleanupSocket(s, ssl, ctx);
			return NULL;
		}
		
		if(f.filetype == APR_DIR) {
			if(!(SSL_CTX_load_verify_locations(ctx, 0, c->CASCertificatePath))) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not load CA certificate path: %s", c->CASCertificatePath);
				CASCleanupSocket(s, ssl, ctx);
				return NULL;
			}
		} else if (f.filetype == APR_REG) {
			if(!(SSL_CTX_load_verify_locations(ctx, c->CASCertificatePath, 0))) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not load CA certificate file: %s", c->CASCertificatePath);
				CASCleanupSocket(s, ssl, ctx);
				return NULL;
			}
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not process Certificate Authority: %s", c->CASCertificatePath);
			CASCleanupSocket(s, ssl, ctx);
			return NULL;
		}
		
		SSL_CTX_set_verify_depth(ctx, c->CASValidateDepth);
	}
	
	ssl = SSL_new(ctx);
	
	if(ssl == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not create an SSL connection to %s", c->CASTicketsURL.hostname);
		CASCleanupSocket(s, ssl, ctx);
		return NULL;
	}
	
	if(SSL_set_fd(ssl, s) == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not bind SSL connection to socket for %s", c->CASTicketsURL.hostname);
		CASCleanupSocket(s, ssl, ctx);
		return NULL;
	}
	
	if(SSL_connect(ssl) <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Could not perform SSL handshake with %s (check CASCertificatePath)", c->CASTicketsURL.hostname);
		CASCleanupSocket(s, ssl, ctx);
		return NULL;
	}
	
	/* validate the server certificate if we require it, first by verifying the CA signature, then by verifying the CN of the certificate to the hostname */
	if(c->CASValidateServer != FALSE) {
		/* SSL_get_verify_result() will return X509_V_OK if the server did not present a certificate, so we must make sure they do present one */
		if(SSL_get_verify_result(ssl) != X509_V_OK || SSL_get_peer_certificate(ssl) == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Certificate not presented or not signed by CA (from %s)", c->CASLoginURL.hostname);
			CASCleanupSocket(s, ssl, ctx);
			return NULL;
		} else if(check_cert_cn(r, c, ctx, SSL_get_peer_certificate(ssl), c->CASTicketsURL.hostname) == FALSE) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: Certificate CN does not match %s", c->CASTicketsURL.hostname);
			CASCleanupSocket(s, ssl, ctx);
			return NULL;
		}
	}
	
	/*
	 * If TGT is NULL, we have to log the user in.
	 */
	if (TGT==NULL || *TGT==0) {
		char *loginData = apr_psprintf(r->pool, "service=%s&username=%s&password=%s%s", getCASService(r, c), escapeString(r, r->user), escapeString(r, d->password), getCASAllow(r));
		int loginDataLength = strlen(loginData);
		loginRequest = apr_psprintf(r->pool, "POST %s HTTP/1.0\nHost: %s\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\n%s", getCASTicketsURL(r, c), c->CASTicketsURL.hostname, loginDataLength, loginData);
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Login request: %s", loginRequest);
		/* send our TGT request */
		if(SSL_write(ssl, loginRequest, (int) strlen(loginRequest)) != strlen(loginRequest)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: unable to write CAS login request to %s%s", c->CASTicketsURL.hostname, getCASTicketsURL(r, c));
			CASCleanupSocket(s, ssl, ctx);
			return NULL;
		}
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Request successfully transmitted");
	
		/* read the response until there is no more */
		i = 0;
		do {
			bytesIn = SSL_read(ssl, loginResponse + i, (sizeof(loginResponse)-i-1));
			i += bytesIn;
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Received %d bytes of response", bytesIn);
		} while (bytesIn > 0 && i < sizeof(loginResponse));
		
		loginResponse[i] = '\0';
		
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "REST response: %s", loginResponse);
		
		if(bytesIn != 0 || i >= sizeof(loginResponse) - 1) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: oversized response received from %s%s", c->CASTicketsURL.hostname, getCASTicketsURL(r, c));
			CASCleanupSocket(s, ssl, ctx);
			return NULL;
		}
		
		CASCleanupSocket(s, ssl, ctx);
		
		ticketStart = NULL;
		char *nextLine;
		for ( nextLine = strtok(loginResponse,"\n\r"); nextLine != NULL; nextLine = strtok(NULL, "\n\r") ) {
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "REST response line: %s", nextLine);

			if (strncasecmp(nextLine, "Location: ", 10) == 0) {
				ticketStart = nextLine+10;
				break;
			}
		}

		if (!ticketStart) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: TGT not found for %s%s", c->CASTicketsURL.hostname, getCASTicketsURL(r, c));
			return (NULL);
		}
		
		return (apr_pstrndup(r->pool, ticketStart, strlen(ticketStart)));
	} else {
		/* At this point we have a TGT, so retrieve a ST */
		char *loginData = apr_psprintf(r->pool, "service=%s%s", getCASService(r, c), getCASAllow(r));
		int loginDataLength = strlen(loginData);
		loginRequest = apr_psprintf(r->pool, "POST %s HTTP/1.0\nHost: %s\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\n%s", TGT,  c->CASTicketsURL.hostname, loginDataLength, loginData);
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Login request: %s", loginRequest);
		/* send our ST request */
		if(SSL_write(ssl, loginRequest, (int) strlen(loginRequest)) != strlen(loginRequest)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: unable to write CAS login request to %s%s", c->CASTicketsURL.hostname, getCASTicketsURL(r, c));
			CASCleanupSocket(s, ssl, ctx);
			return NULL;
		}
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Request successfully transmitted");

		/* read the response until there is no more */
		i = 0;
		do {
			bytesIn = SSL_read(ssl, loginResponse + i, (sizeof(loginResponse)-i-1));
			i += bytesIn;
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Received %d bytes of response", bytesIn);
		} while (bytesIn > 0 && i < sizeof(loginResponse));
		
		loginResponse[i] = '\0';
				
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "REST response: %s", loginResponse);
		
		if(bytesIn != 0 || i >= sizeof(loginResponse) - 1) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: oversized response received from %s%s", c->CASTicketsURL.hostname, getCASTicketsURL(r, c));
			CASCleanupSocket(s, ssl, ctx);
			return NULL;
		}
		
		CASCleanupSocket(s, ssl, ctx);
		
		ticketStart = NULL;
		char *nextLine;
		for ( nextLine = strtok(loginResponse,"\n\r"); nextLine != NULL; nextLine = strtok(NULL, "\n\r") ) {
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "REST response line: %s", nextLine);
			ticketStart = nextLine;
		}
		
		if (!ticketStart) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_AUTH_CAS: ST not found for %s%s", c->CASTicketsURL.hostname, getCASTicketsURL(r, c));
			return (NULL);
		}
		
		return (apr_pstrndup(r->pool, ticketStart, strlen(ticketStart)));
	}	
}

static void note_basic_auth_failure(request_rec *r)
{
    apr_table_setn(r->err_headers_out,
                   (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate"
                                                   : "WWW-Authenticate",
                   apr_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r),
                               "\"", NULL));
}

/* basic CAS module logic */
static int cas_authenticate(request_rec *r)
{
	char *cookieString = NULL;
	char *ticket = NULL;
	char *remoteUser = NULL;
	char *SFUauthtype = NULL;
	char *SFUmaillist = NULL;
	char *sent_user, *sent_pw;
	cas_cfg *c;
	cas_dir_cfg *d;
	apr_byte_t ssl;
	apr_byte_t parametersRemoved = FALSE;
	apr_port_t port = r->connection->local_addr->port;
	apr_byte_t printPort = FALSE;
	
	char *newLocation = NULL;

	/* Do nothing if we are not the authenticator */
	if(apr_strnatcasecmp((const char *) ap_auth_type(r), "cas") &&
		apr_strnatcasecmp((const char *) ap_auth_type(r), "basic"))
		return DECLINED;
#ifdef BROKEN
	if(r->method_number == M_POST) {
		/* read the POST data here to determine if it is a SAML LogoutRequest and handle accordingly */
		ap_add_input_filter("CAS", NULL, r, r->connection);
	}
#endif

	c = ap_get_module_config(r->server->module_config, &auth_cas_module);
	d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Entering cas_authenticate()");
	ssl = isSSL(r);
	
	// Check to see if we should be doing CAS redirection for authentication or Basic authentication
	if (d->useauthtype==CAS_AUTHTYPE_BASIC || (d->useauthtype==CAS_AUTHTYPE_BOTH && 0==apr_strnatcasecmp((const char *) ap_auth_type(r), "basic"))) {
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Switching to Basic authentication. useauthtype=%s ap_auth_type=%s", (d->useauthtype==CAS_AUTHTYPE_BASIC)?"basic":(d->useauthtype==CAS_AUTHTYPE_BOTH)?"both":"unknown", (const char *) ap_auth_type(r));
		// If we were asked to do Basic authentication, we have to over-ride ap_auth_type to make it Basic. This is so that
		// Apache will correctly use Basic authentication (even though we are using CAS authentication
		// to authenticate the user		
		r->ap_auth_type = "Basic";
	} else {
		//r->ap_auth_type = "CAS";
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Using CAS authentication. r->ap_auth_type=%s ap_auth_type(r)=%s", r->ap_auth_type, (const char *) ap_auth_type(r));
	}
		
RETRYBASIC:
	if (r->ap_auth_type!=NULL && 0==apr_strnatcasecmp((const char *) r->ap_auth_type, "basic")) {
		if(c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Entering Basic authentication. useauthtype=%s ap_auth_type=%s", (d->useauthtype==CAS_AUTHTYPE_BASIC)?"basic":(d->useauthtype==CAS_AUTHTYPE_BOTH)?"both":"unknown", (const char *) ap_auth_type(r));
#if MODULE_MAGIC_NUMBER_MAJOR < 20120211
		{
		    core_dir_config *conf;
			conf = (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module);
			conf->ap_auth_type = r->ap_auth_type;
			if (!ap_auth_name(r)) {
				conf->ap_auth_name = "SFU CAS";
			}
		}
#endif
		// Now check to see if the browser provided a user/pw
		{
			const char *auth_line;
			char *decoded_line;
			int length;

			/* Get the appropriate header */
			auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                              ? "Proxy-Authorization"
                                              : "Authorization");
											  
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: getting basic auth header = %s", (!auth_line)?"NULL":auth_line);

			if (!auth_line) {
				note_basic_auth_failure(r);
				return HTTP_UNAUTHORIZED;
			}
			if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
				/* Client tried to authenticate using wrong auth scheme */
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "MOD_AUTH_CAS: client used wrong authentication scheme: %s", r->uri);
				note_basic_auth_failure(r);
				return HTTP_UNAUTHORIZED;
			}

			/* Skip leading spaces. */
			while (*auth_line==' ') {
				auth_line++;
			}

			decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
			length = apr_base64_decode(decoded_line, auth_line);
			/* Null-terminate the string. */
			decoded_line[length] = '\0';

			sent_user = ap_getword_nulls(r->pool, (const char**)&decoded_line, ':');
			sent_pw = decoded_line;
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: found basic auth user = %s", sent_user);

			/* set the user, even though the user is unauthenticated at this point */
			r->user = sent_user;
			d->password = sent_pw;
		}
		// If we have a user logged in, try to get a service ticket from CAS, otherwise fall
		// through without a ticket so the user will be prompted for an id/password
		if (r->user == NULL) {
			note_basic_auth_failure(r);
			return HTTP_UNAUTHORIZED;
		} else {
			/*
			 * Check to see if we have a cache entry for this user
			 */
			if(isValidCASCookie(r, c, createBasicCASCacheName(r), &remoteUser, &SFUauthtype, &SFUmaillist, &d->password)) {
				d->authtype = SFUauthtype;
				d->maillist = SFUmaillist;
				r->user = remoteUser;
				if(d->CASAuthNHeader != NULL)
					apr_table_set(r->headers_in, d->CASAuthNHeader, remoteUser);
					// Setup environment variables for SFU items
					apr_table_t *e;
					if (apr_is_empty_table(r->subprocess_env)) {
						e = r->subprocess_env;
					} else {
						e = apr_table_make(r->pool, 5);
					}
					if (SFUauthtype!=NULL)
						apr_table_addn(e, "REMOTE_USER_AUTHTYPE", SFUauthtype);
					if (SFUmaillist!=NULL)
						apr_table_addn(e, "REMOTE_USER_MAILLIST", SFUmaillist);
					if (e != r->subprocess_env)
						apr_table_overlap(r->subprocess_env, e, APR_OVERLAP_TABLES_SET);
					return OK;
				}
			/*
			 * In order to get a ticket in Basic mode, we need to pass the id/password to CAS
			 */
			char *TGT = CAS_tickets(r, c, d, NULL);
			if (TGT==NULL) {
				note_basic_auth_failure(r);
				return HTTP_UNAUTHORIZED;
			}
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: got TGT ticket = %s", TGT);
			ticket = CAS_tickets(r, c, d, TGT);
			if (ticket==NULL) {
				note_basic_auth_failure(r);
				return HTTP_UNAUTHORIZED;
			}
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_AUTH_CAS: got service ticket = %s", ticket);
		}			
	} else {

		/* the presence of a ticket overrides all */
		ticket = getCASTicket(r);
		cookieString = getCASCookie(r, (ssl ? d->CASSecureCookie : d->CASCookie));
		if (cookieString!=NULL)
			if(!isValidCASCookie(r, c, cookieString, &remoteUser, &SFUauthtype, &SFUmaillist, &d->password)) 
				cookieString = NULL;
	}
	
	parametersRemoved = removeCASParams(r);
	
	/* first, handle the gateway case */
	if (c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Gateway check gateway=(%s) path=(%s) cookiestring=(%s)", d->CASGateway, r->parsed_uri.path, cookieString);
	if(d->CASGateway != NULL && strncmp(d->CASGateway, r->parsed_uri.path, strlen(d->CASGateway)) == 0 && ticket == NULL && cookieString == NULL) {
		cookieString = getCASCookie(r, d->CASGatewayCookie);
		if(cookieString == NULL) { /* they have not made a gateway trip yet */
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Gateway initial access (%s)", r->parsed_uri.path);
			setCASCookie(r, d->CASGatewayCookie, "TRUE", ssl);
			redirectRequest(r, c);
			return HTTP_MOVED_TEMPORARILY;
		} else {
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Gateway anonymous authentication (%s)", r->parsed_uri.path);
			/* do not set a user, but still allow anonymous access */
			return OK;
		}
	}
	
	/* now, handle when a ticket is present (this will also catch gateway users since ticket != NULL on their trip back) */
	d->haveTicket = 0;
	if(ticket != NULL) {
		if(isValidCASTicket(r, c, ticket, &remoteUser, &SFUauthtype, &SFUmaillist, &d->password)) {
			// This is just a flag that causes a redirect to CAS to force a login.
			d->haveTicket = 1;
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Values from isValidCASTicket remoteUser=%s SFUauthtype=%s SFUMaillist=%s password=%s", remoteUser, SFUauthtype, SFUmaillist, d->password);
			cookieString = createCASCookie(r, remoteUser, ticket, SFUauthtype, SFUmaillist);
			setCASCookie(r, (ssl ? d->CASSecureCookie : d->CASCookie), cookieString, ssl);
			r->user = remoteUser;
			if(d->CASAuthNHeader != NULL)
				apr_table_set(r->headers_in, d->CASAuthNHeader, remoteUser);
			if (d->CASAuthTypeHeader != NULL && SFUauthtype != NULL)
				apr_table_set(r->headers_in, d->CASAuthTypeHeader, SFUauthtype);
			if (d->CASAuthMaillistHeader != NULL && SFUmaillist != NULL)
				apr_table_set(r->headers_in, d->CASAuthMaillistHeader, SFUmaillist);

            // Setup environment variables for SFU items
            apr_table_t *e;
            if (apr_is_empty_table(r->subprocess_env)) {
                e = r->subprocess_env;
            } else {
                e = apr_table_make(r->pool, 5);
            }
			if (SFUauthtype!=NULL) {
				apr_table_addn(e, "REMOTE_USER_AUTHTYPE", SFUauthtype);
				d->authtype = SFUauthtype;
			}
			if (SFUmaillist!=NULL) {
				apr_table_addn(e, "REMOTE_USER_MAILLIST", SFUmaillist);
				d->maillist = SFUmaillist;
			}
      if (e != r->subprocess_env)
                apr_table_overlap(r->subprocess_env, e, APR_OVERLAP_TABLES_SET);

			if(parametersRemoved == TRUE) {
				if(ssl == TRUE && port != 443) 
					printPort = TRUE;
				else if(port != 80)
					printPort = TRUE;
				
				if(c->CASRootProxiedAs.is_initialized) {
					newLocation = apr_psprintf(r->pool, "%s%s%s%s", apr_uri_unparse(r->pool, &c->CASRootProxiedAs, 0), r->uri, ((r->args != NULL) ? "?" : ""), ((r->args != NULL) ? escapeString(r, r->args) : ""));
				} else {
#ifdef APACHE2_0
					if(printPort == TRUE)
						newLocation = apr_psprintf(r->pool, "%s://%s:%u%s%s%s", ap_http_method(r), r->server->server_hostname, r->connection->local_addr->port, r->uri, ((r->args != NULL) ? "?" : ""), ((r->args != NULL) ? r->args : ""));
					else
						newLocation = apr_psprintf(r->pool, "%s://%s%s%s%s", ap_http_method(r), r->server->server_hostname, r->uri, ((r->args != NULL) ? "?" : ""), ((r->args != NULL) ? r->args : ""));
#else
					if(printPort == TRUE)
						newLocation = apr_psprintf(r->pool, "%s://%s:%u%s%s%s", ap_http_scheme(r), r->server->server_hostname, r->connection->local_addr->port, r->uri, ((r->args != NULL) ? "?" : ""), ((r->args != NULL) ? r->args : ""));
					else
						newLocation = apr_psprintf(r->pool, "%s://%s%s%s%s", ap_http_scheme(r), r->server->server_hostname, r->uri, ((r->args != NULL) ? "?" : ""), ((r->args != NULL) ? r->args : ""));
#endif
				}
				apr_table_add(r->headers_out, "Location", newLocation);
				return HTTP_MOVED_TEMPORARILY;
			} else {
				return OK;
			}
		} else {
			/* If we get here, we just fall through and get redirected back to CAS */
			/* sometimes, pages that automatically refresh will re-send the ticket parameter, so let's check any cookies presented or return an error if none */
			//if(cookieString == NULL)
			//	return HTTP_UNAUTHORIZED;
		}
	}
	
	if(cookieString == NULL) {
		/* redirect the user to the CAS server since they have no cookie and no ticket */
		if (r->ap_auth_type!=NULL && 0==apr_strnatcasecmp((const char *) r->ap_auth_type, "basic")) {
			note_basic_auth_failure(r);
			return HTTP_UNAUTHORIZED;
		}
		redirectRequest(r, c);
		return HTTP_MOVED_TEMPORARILY;
	} else {
		if(isValidCASCookie(r, c, cookieString, &remoteUser, &SFUauthtype, &SFUmaillist, &d->password)) {
			if(c->CASDebug)
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Values from isValidCASCookie remoteUser=%s SFUauthtype=%s SFUMaillist=%s password=%s", remoteUser, SFUauthtype, SFUmaillist, d->password);
			d->authtype = SFUauthtype;
			d->maillist = SFUmaillist;
			r->user = remoteUser==NULL?"":remoteUser;
			if(d->CASAuthNHeader != NULL)
				apr_table_set(r->headers_in, d->CASAuthNHeader, r->user);
			if (d->CASAuthTypeHeader != NULL && SFUauthtype != NULL)
				apr_table_set(r->headers_in, d->CASAuthTypeHeader, SFUauthtype);
			if (d->CASAuthMaillistHeader != NULL && SFUmaillist != NULL)
				apr_table_set(r->headers_in, d->CASAuthMaillistHeader, SFUmaillist);

			// Setup environment variables for SFU items
			apr_table_t *e;
			if (apr_is_empty_table(r->subprocess_env)) {
					e = r->subprocess_env;
			} else {
					e = apr_table_make(r->pool, 5);
			}
			if (SFUauthtype!=NULL) {
				apr_table_addn(e, "REMOTE_USER_AUTHTYPE", SFUauthtype);
				d->authtype = SFUauthtype;
			}
			if (SFUmaillist!=NULL) {
				apr_table_addn(e, "REMOTE_USER_MAILLIST", SFUmaillist);
				d->maillist = SFUmaillist;
			}
			if (e != r->subprocess_env)
					apr_table_overlap(r->subprocess_env, e, APR_OVERLAP_TABLES_SET);
			return OK;
		} else {
			/* maybe the cookie expired, have the user get a new service ticket */
			if (r->ap_auth_type!=NULL && 0==apr_strnatcasecmp((const char *) r->ap_auth_type, "basic")) goto RETRYBASIC;
			redirectRequest(r, c);
			return HTTP_MOVED_TEMPORARILY;
		}
	}

	if (r->ap_auth_type!=NULL && 0==apr_strnatcasecmp((const char *) r->ap_auth_type, "basic")) {
		note_basic_auth_failure(r);
		return HTTP_UNAUTHORIZED;
	} else {		
		redirectRequest(r, c);
		return HTTP_MOVED_TEMPORARILY;
	}
}

static int cas_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s)
{
	cas_cfg *c = ap_get_module_config(s->module_config, &auth_cas_module);
	apr_finfo_t f;

	if(apr_stat(&f, c->CASCookiePath, APR_FINFO_TYPE, pool) == APR_INCOMPLETE) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "MOD_AUTH_CAS: Could not find CASCookiePath '%s'", c->CASCookiePath);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if(f.filetype != APR_DIR || c->CASCookiePath[strlen(c->CASCookiePath)-1] != '/') {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "MOD_AUTH_CAS: CASCookiePath '%s' is not a directory or does not end in a trailing '/'!", c->CASCookiePath);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

// Added 
// Similar to cas_check_authorization in the new standard mod_auth_cas for 2.4
#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211

// require valid-sfu-user
authz_status cas_check_authz_valid_sfu_user(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	// Each parsed .htaccess will be stored in *d 
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if (!strcasecmp(d->authtype, "sfu")) return AUTHZ_GRANTED;

	return AUTHZ_DENIED;
}

static const authz_provider authz_valid_sfu_user_provider =
{
        &cas_check_authz_valid_sfu_user,
        NULL,
};


// require sfu-user [uid1] [uid2] [!mail-list1] [!mail-list2]
authz_status cas_check_authz_sfu_user(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	// cas_cfg is the global configuration of this module, i.e., mod_auth_cas
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);
	
	// Each parsed .htaccess will be stored in *d 
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	const char *t, *w;

	t = require_line;
	if (c->CASDebug) 
	{
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "*****The current require line: %s", require_line); 
	}
	
	// Use w[0] to check if w is a NULL string
	// Parse the require line to look at each word
	while ((w = ap_getword_conf(r->pool, &t)) && w[0])
	{
		if (w[0] == '!') {
			if (d->maillist!=NULL && !strcasecmp(w+1, d->maillist)) return AUTHZ_GRANTED;
		} else {
			if (!strcasecmp(d->authtype, "sfu") && !strcasecmp(w, r->user)) return AUTHZ_GRANTED;
		}	
	}
	
	return AUTHZ_DENIED;
}

static const authz_provider authz_sfu_user_provider =
{
        &cas_check_authz_sfu_user,
        NULL,
};


// require valid-sfu-staff
authz_status cas_check_authz_valid_sfu_staff(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	// Each parsed .htaccess will be stored in *d 
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if (!strcasecmp(d->authtype, "staff")) return AUTHZ_GRANTED;
	// TODO:
	// Check the attributes returned from CAS p3/serviceValidate

	return AUTHZ_DENIED;
}

static const authz_provider authz_valid_sfu_staff_provider =
{
        &cas_check_authz_valid_sfu_staff,
        NULL,
};


authz_status cas_check_authz_valid_sfu_student(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	// Each parsed .htaccess will be stored in *d 
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if (!strcasecmp(d->authtype, "student")) return AUTHZ_GRANTED;

	return AUTHZ_DENIED;
}

static const authz_provider authz_valid_sfu_student_provider =
{
        &cas_check_authz_valid_sfu_student,
        NULL,
};


authz_status cas_check_authz_valid_sfu_sponsored(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	// Each parsed .htaccess will be stored in *d 
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if (!strcasecmp(d->authtype, "sponsored")) return AUTHZ_GRANTED;

	return AUTHZ_DENIED;

}

static const authz_provider authz_valid_sfu_sponsored_provider =
{
        &cas_check_authz_valid_sfu_sponsored,
        NULL,
};


authz_status cas_check_authz_valid_sfu_external(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	// Each parsed .htaccess will be stored in *d 
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if (!strcasecmp(d->authtype, "external")) return AUTHZ_GRANTED;

	return AUTHZ_DENIED;
}

static const authz_provider authz_valid_sfu_external_provider =
{
        &cas_check_authz_valid_sfu_external,
        NULL,
};


// require valid-alumni-user
authz_status cas_check_authz_valid_alumni_user(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	// Each parsed .htaccess will be stored in *d 
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if (!strcasecmp(d->authtype, "alumni")) return AUTHZ_GRANTED;

	return AUTHZ_DENIED;
}

static const authz_provider authz_valid_alumni_user_provider =
{
        &cas_check_authz_valid_alumni_user,
        NULL,
};


// require alumni-user [user1] [user2] 
authz_status cas_check_authz_alumni_user(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
	const char *t, *w;

	if (strcasecmp(d->authtype, "alumni")) return AUTHZ_DENIED;

	t = require_line;
	if (c->CASDebug) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "*****The current require line: %s", require_line); 
	}
	
	int len = strlen(r->user);
	if (strchr(r->user, '@')) {
		len = strchr(r->user, '@') - r->user;
	}
	
	// Use w[0] to check if w is a NULL string
	// Parse the require line to look at each word
	while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
		if (!strncmp(w, r->user, len)) return AUTHZ_GRANTED;	
	}
	
	return AUTHZ_DENIED;
}

static const authz_provider authz_alumni_user_provider =
{
        &cas_check_authz_alumni_user,
        NULL,
};


// See the code in cas_user_access(request_rec *r) 
// require valid-user
authz_status cas_check_authz_valid_user(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	// Check if there is a .htpasswd
	// if there isn't a .htpasswd, treat like "require valid-sfu-user"
	if (d->pwfile == NULL) return cas_check_authz_valid_sfu_user(r, require_line, parsed_require_line);
	
	// Open and parse the .htpasswd 
	ap_configfile_t *f;
	char l[CAS_MAX_RESPONSE_SIZE+1];
					
	if(c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_check_authz_valid_user: Trying to open htpasswd file '%s'", d->pwfile==NULL?"(NULL)":d->pwfile);
	if (APR_SUCCESS != ap_pcfg_openfile(&f, r->pool, d->pwfile)) return AUTHZ_GENERAL_ERROR;
	if (c->CASDebug)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_check_authz_valid_user: Successfully opened '%s'", d->pwfile);
					
	while (!(ap_cfg_getline(l, CAS_MAX_RESPONSE_SIZE, f))) {
		if (c->CASDebug)
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_check_authz_valid_user: Line read from htpasswd file '%s'", l);
		if ((l[0] == '#') || (l[0] == 0)) continue; // ignore comment or blank lines
		if (l[0] == '+') {
			if (l[1] == '!') {
				if (d->maillist!=NULL && !strcasecmp(l+2,d->maillist)) {ap_cfg_closefile(f);return AUTHZ_GRANTED;}
			} else {
				if (!strcasecmp(d->authtype,"sfu")) {
					if (l[1] == 0) {ap_cfg_closefile(f);return AUTHZ_GRANTED;}
					else if (!strcmp(l+1, r->user)) {ap_cfg_closefile(f);return AUTHZ_GRANTED;}
				}
			}
		} else if (!strcasecmp(d->authtype, "apache") && 
				!strncmp(l, r->user, strlen(r->user)) &&
				l[strlen(r->user)]==':') {ap_cfg_closefile(f);return AUTHZ_GRANTED;}
	}
	ap_cfg_closefile(f);
	return AUTHZ_DENIED;
}

static const authz_provider authz_valid_user_provider =
{
        &cas_check_authz_valid_user,
        NULL,
};

// require user
authz_status cas_check_authz_user(request_rec *r, const char *require_line, const void *parsed_require_line)
{
	// if there is no AuthUserFile present, treat like sfu-user,
	// else check the AuthUserFile for authentication information
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);

	if (d->pwfile == NULL) return cas_check_authz_sfu_user(r, require_line, parsed_require_line);

	const char *t, *w;

	t = require_line;
	while ((w = ap_getword_conf(r->pool, &t)) && w[0])
	{
		if (!strcasecmp(d->authtype,"apache") && !strcmp(w, r->user)) return AUTHZ_GRANTED;
		if (!strcasecmp(d->authtype,"sfu") && !strcmp(w, r->user)) return AUTHZ_GRANTED;
	}
	return AUTHZ_DENIED;
}

static const authz_provider authz_user_provider =
{
        &cas_check_authz_valid_user,
        NULL,
};

#else

// Checking authorization
static int cas_user_access(request_rec *r)
{
	cas_cfg *c = ap_get_module_config(r->server->module_config, &auth_cas_module);
	cas_dir_cfg *d = ap_get_module_config(r->per_dir_config, &auth_cas_module);
    const apr_array_header_t *reqs_arr = ap_requires(r);
	int m = r->method_number;
    char *user = r->user;
	char *authtype = d->authtype;
	char *maillist = d->maillist;
    require_line *reqs;
    const char *t, *w;
    register int x;

	if (user==NULL || user[0]==0) {
		/* No user, so perhaps gateway was specified */
		if (d->CASGateway!=NULL && d->CASGateway[0]) return OK;
	}
	
	/* If no require lines, don't let anyone in */
    if (reqs_arr) {
		
		reqs = (require_line *)reqs_arr->elts;
		int req_count = reqs_arr->nelts;
		
		/* 
		 *  If the user is an "apache" account, check the password in the htpasswd file
		 *	We will set req_count to 0 so that the require line check is skipped if
		 *  the password check fails.
		 */
		 // Commented because Ray think this block should be called earlier, i.e., in isValidCASTicket routine
		 
// 		if (!strcasecmp(authtype,"apache")) {
// 			ap_configfile_t *f;
// 			char l[CAS_MAX_RESPONSE_SIZE+1];
// 			
// 			/* We will set the request count to 0 assuming the password check fails. It will be reset if it passes. */
// 			req_count = 0;
// 			if (d->password==NULL) d->password="";
// 			
// 			if(c->CASDebug)
// 				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_user_access: Trying to open htpasswd file '%s'", d->pwfile==NULL?"(NULL)":d->pwfile);
// 			if (APR_SUCCESS == ap_pcfg_openfile(&f, r->pool, d->pwfile)) {
// 				if (c->CASDebug)
// 					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_user_access: Successfully opened '%s'", d->pwfile);
// 			
// 				while (!(ap_cfg_getline(l, CAS_MAX_RESPONSE_SIZE, f))) {
// 					if ((l[0] == '#') || (l[0] == 0)) continue; // ignore comment or blank lines
// 					if (l[0] == '+') continue; // an SFU line
// 					if (!strncmp(l, user, strlen(user)) && l[strlen(user)]==':') {
// 						if (APR_SUCCESS == apr_password_validate(d->password, l+strlen(user)+1)) {
// 							if (c->CASDebug)
// 								ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_user_access: Successfully validated password for '%s'", user);
// 							req_count=reqs_arr->nelts; 
// 							break;
// 						}
// 					}
// 				}
// 			} else {
// 				if (c->CASDebug)
// 					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_user_access: Unable to opened '%s'", d->pwfile);
// 			}
// 		}
		
		for (x = 0; x < req_count; x++) {
			
			if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) {
				continue;
			}
			
			t = reqs[x].requirement;
			w = ap_getword_white(r->pool, &t);
			
			if (!strcasecmp(w, "group")) {
				w = ap_getword_conf(r->pool, &t);
				if (d->gpfile!=NULL) {
					ap_configfile_t *f;
					char l[CAS_MAX_RESPONSE_SIZE+1];
					const char *ll;
					char *group_name;
					int group_len;
					if (APR_SUCCESS == ap_pcfg_openfile(&f, r->pool, d->gpfile)) {
						while (!(ap_cfg_getline(l, CAS_MAX_RESPONSE_SIZE, f))) {
							if (c->CASDebug)
								ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_user_access: Line read from group file '%s'", l);
							if ((l[0] == '#') || (l[0] == 0)) continue; // ignore comment or blank lines
							ll = l;
							
							group_name = ap_getword(r->pool, &ll, ':');
							group_len = strlen(group_name);
							
							while (group_len && isspace(*(group_name + group_len - 1))) {
								--group_len;
							}
							if (strncmp(w, group_name, group_len+1)) continue;
							while (ll[0]) {
								w = ap_getword_conf(r->pool, &ll);
								if (!strcmp(w, user)) return OK;
							}
						}
						ap_cfg_closefile(f);						
					}
				}
			} else if (!strcasecmp(w, "valid-sfu-user")) {
				// allow any SFU user in
				if (!strcasecmp(authtype,"sfu")) return OK;
			} else if (!strcasecmp(w, "sfu-user")) {
				// allow specific SFU user in
				while (*t) {
					w = ap_getword_conf(r->pool, &t);
					if (w[0] == '!') {
						if (maillist!=NULL && !strcasecmp(w+1,maillist)) return OK;
					} else {
						if (!strcasecmp(authtype,"sfu") && !strcasecmp(w, user)) return OK;
					}
				}
			} else if (!strcasecmp(w, "valid-sfu-staff")) {
				// allow staff SFU user
				if (!strcasecmp(authtype,"staff")) return OK;
			} else if (!strcasecmp(w, "valid-sfu-faculty")) {
				// allow faculty SFU user
				if (!strcasecmp(authtype,"faculty")) return OK;
			} else if (!strcasecmp(w, "valid-sfu-student")) {
				// allow student SFU user
				if (!strcasecmp(authtype,"student")) return OK;
			} else if (!strcasecmp(w, "valid-sfu-sponsored")) {
				// allow sponsored SFU user
				if (!strcasecmp(authtype,"sponsored")) return OK;
			} else if (!strcasecmp(w, "valid-sfu-external")) {
				// allow external SFU user
				if (!strcasecmp(authtype,"external")) return OK;
			} else if (!strcasecmp(w, "valid-alumni-user")) {
				// allow any alumni user
				if (!strcasecmp(authtype,"alumni")) return OK;
			} else if (!strcasecmp(w, "alumni-user")) {
				// Allow specific alumni users
				if (strcasecmp(authtype,"alumni")) continue;
				// remove the "@alumni.sfu.ca from the account if it is there
				int len = strlen(user);
				if (strchr(user, '@')) {
					len = strchr(user, '@')-user;
				}
				while (*t) {
					w = ap_getword_conf(r->pool, &t);
					if (!strncmp(w, user, len)) return OK;
				}
			} else if (!strcasecmp(w, "valid-user")) {
				// if there is no AuthUserFile present, treat like valid-sfu-user,
				// else check the AuthUserFile for authentication information
				if (d->pwfile == NULL) {
					if (!strcasecmp(authtype,"sfu")) return OK;
				} else {
					ap_configfile_t *f;
					char l[CAS_MAX_RESPONSE_SIZE+1];
					const char *rpw, *w;
					
					if(c->CASDebug)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_user_access: Trying to open htpasswd file '%s'", d->pwfile==NULL?"(NULL)":d->pwfile);
					if (APR_SUCCESS != ap_pcfg_openfile(&f, r->pool, d->pwfile)) continue;
					if (c->CASDebug)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_user_access: Successfully opened '%s'", d->pwfile);
					
					while (!(ap_cfg_getline(l, CAS_MAX_RESPONSE_SIZE, f))) {
						if (c->CASDebug)
							ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cas_user_access: Line read from htpasswd file '%s'", l);
						if ((l[0] == '#') || (l[0] == 0)) continue; // ignore comment or blank lines
						if (l[0] == '+') {
							if (l[1] == '!') {
								if (maillist!=NULL && !strcasecmp(l+2,maillist)) {ap_cfg_closefile(f);return OK;}
							} else {
								if (!strcasecmp(authtype,"sfu")) {
									if (l[1] == 0) {ap_cfg_closefile(f);return OK;}
									else if (!strcmp(l+1, user)) {ap_cfg_closefile(f);return OK;}
								}
							}
						} else if (!strcasecmp(authtype, "apache") && 
								   !strncmp(l, user, strlen(user)) &&
								   l[strlen(user)]==':') {ap_cfg_closefile(f);return OK;}
					}
					ap_cfg_closefile(f);
				}
			} else if (!strcasecmp(w, "user")) {
				// if there is no AuthUserFile present, treat like sfu-user,
				// else check the AuthUserFile for authentication information
				if (d->pwfile == NULL) {
					while (*t) {
						w = ap_getword_conf(r->pool, &t);
						if (w[0] == '!') {
							if (maillist!=NULL && !strcasecmp(w+1,maillist)) return OK;
						} else {
							if (!strcasecmp(authtype,"sfu") && !strcmp(w, user)) return OK;
						}
					}
				} else {
					while (*t) {
						w = ap_getword_conf(r->pool, &t);
						if (!strcasecmp(authtype,"apache") && !strcmp(w, user)) return OK;
						if (!strcasecmp(authtype,"sfu") && !strcmp(w, user)) return OK;
					}
				}
			}
		}
	}
	
    if (!d->authoritative) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "access to %s failed, reason: user '%s' does not meet 'require'ments to be allowed access",
		r->uri, user);

	if (r->ap_auth_type!=NULL && 0==apr_strnatcasecmp((const char *) r->ap_auth_type, "basic")) {
		note_basic_auth_failure(r);
		return HTTP_UNAUTHORIZED;
	} else {
		/* At this point we need to get CAS to reauthenticate the user, so set haveTicket to true so that redirectRequest will force a login */
		d->haveTicket = 1;
		redirectRequest(r, c);
		return HTTP_MOVED_TEMPORARILY;
	}
}
#endif

#ifdef BROKEN
static apr_status_t cas_in_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {
	apr_bucket *b, *d;
	apr_size_t len;
	const char *str;
	char *data;

	/* do not operate on subrequests */
	if (ap_is_initial_req(f->r) == FALSE) {
		ap_remove_input_filter(f);
		return (ap_pass_brigade(f->next, bb));
	}

	ap_get_brigade(f->next, bb, mode, readbytes, CAS_MAX_RESPONSE_SIZE);

	/* get the first bucket from the brigade */
	b = APR_BRIGADE_FIRST(bb);

	/* if this bucket is NULL, the brigade is empty, and we should return SUCCESS to higher filters */
	if(b->type == NULL)
		return APR_SUCCESS;

	/* read from the bucket - if for some reason the logoutRequest comes in more than 1 bucket, we will not be able to process it */
	apr_bucket_read(b, &str, &len, APR_BLOCK_READ);
	
	data = apr_pstrndup(f->r->pool, str, len);

	CASSAMLLogout(f->r, data);

	/* put the data back in the brigade */
	d = apr_bucket_transient_create(str, len, f->r->connection->bucket_alloc);  // transient buckets contain stack data
	apr_bucket_setaside(d, f->c->pool); // setaside ensures that the stack data has a long enough lifetime
	APR_BUCKET_INSERT_AFTER(b, d); // insert bucket C after B in the brigade
	APR_BUCKET_REMOVE(b); // remove bucket B (we have consumed its contents)
	apr_bucket_destroy(b); // destroy the bucket we have consumed

	/* we're done here */
	ap_remove_input_filter(f);

	return(ap_pass_brigade(f->next, bb));
}
#endif

/*
 * It tells Apache that these are capable of doing authentication / authorization 
 */
static void cas_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(cas_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	
  // Copied code from mod_auth_cas 2.4 
  // ap_hook_auth_checker(cas_user_access, NULL, NULL, APR_HOOK_MIDDLE);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211
	/*
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "cas-attribute",
		AUTHZ_PROVIDER_VERSION,
		&authz_cas_provider, AP_AUTH_INTERNAL_PER_CONF);
	 */
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-sfu-user",
		AUTHZ_PROVIDER_VERSION,
		&authz_valid_sfu_user_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-sfu-staff",
		AUTHZ_PROVIDER_VERSION,
		&authz_valid_sfu_staff_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-sfu-student",
		AUTHZ_PROVIDER_VERSION,
		&authz_valid_sfu_student_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-sfu-sponsored",
		AUTHZ_PROVIDER_VERSION,
		&authz_valid_sfu_sponsored_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-sfu-external",
		AUTHZ_PROVIDER_VERSION,
		&authz_valid_sfu_external_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "sfu-user",
		AUTHZ_PROVIDER_VERSION,
		&authz_sfu_user_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-alumni-user",
		AUTHZ_PROVIDER_VERSION,
		&authz_valid_alumni_user_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "alumni-user",
		AUTHZ_PROVIDER_VERSION,
		&authz_alumni_user_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "user",
		AUTHZ_PROVIDER_VERSION,
		&authz_user_provider, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-user",
		AUTHZ_PROVIDER_VERSION,
		&authz_valid_user_provider, AP_AUTH_INTERNAL_PER_CONF);
#else
	/* make sure we run before mod_authz_user so that a "require valid-user"
	 *  directive doesn't just automatically pass us. */
	static const char *const authzSucc[] = { "mod_authz_user.c", NULL };
	// ap_hook_auth_checker(cas_authorize, NULL, authzSucc, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(cas_user_access, NULL, authzSucc, APR_HOOK_MIDDLE);
#endif

#ifdef BROKEN
	ap_register_input_filter("CAS", cas_in_filter, NULL, AP_FTYPE_RESOURCE); 
#endif

  // Copied code from mod_auth_cas 2.4 
	// ap_hook_check_user_id(cas_authenticate, NULL, NULL, APR_HOOK_MIDDLE);
	// Authentication with CAS 
#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211
	ap_hook_check_authn(
		cas_authenticate,
		NULL,
		NULL,
		APR_HOOK_MIDDLE,
		AP_AUTH_INTERNAL_PER_URI);
#elif MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_hook_check_access_ex(
		cas_authenticate,
		NULL,
		NULL,
		APR_HOOK_MIDDLE,
		AP_AUTH_INTERNAL_PER_URI);
#else
	ap_hook_check_user_id(cas_authenticate, NULL, NULL, APR_HOOK_MIDDLE);
#endif
	
}

static const command_rec cas_cmds [] = {
	AP_INIT_TAKE1("CASVersion", cfg_readCASParameter, (void *) cmd_version, RSRC_CONF, "Set CAS Protocol Version (1 or 2)"),
	AP_INIT_TAKE1("CASDebug", cfg_readCASParameter, (void *) cmd_debug, RSRC_CONF, "Enable or disable debug mode (On or Off)"),
	/* cas protocol options */
	AP_INIT_TAKE1("CASScope", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASScope), ACCESS_CONF|OR_AUTHCFG, "Define the scope that this CAS sessions is valid for (e.g. /app/ will validate this session for /app/*)"),
	AP_INIT_TAKE1("CASRenew", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASRenew), ACCESS_CONF|OR_AUTHCFG, "Force credential renew (/app/secure/ will require renew on /app/secure/*)"),
	AP_INIT_TAKE1("CASGateway", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASGateway), ACCESS_CONF|OR_AUTHCFG, "Allow anonymous access if no CAS session is established on this path (e.g. /app/insecure/ will allow gateway access to /app/insecure/*), CAS v2 only"),
	AP_INIT_TAKE1("CASAuthNHeader", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASAuthNHeader), ACCESS_CONF|OR_AUTHCFG, "Specify the HTTP header variable to set with the name of the CAS authenticated user.  By default no headers are added."),
	AP_INIT_TAKE1("CASAuthTypeHeader", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASAuthTypeHeader), ACCESS_CONF|OR_AUTHCFG, "Specify the HTTP header variable to set with the name of the CAS auth type.  By default no headers are added."),
	AP_INIT_TAKE1("CASAuthMaillistHeader", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASAuthMaillistHeader), ACCESS_CONF|OR_AUTHCFG, "Specify the HTTP header variable to set with the name of the CAS matched maillist.  By default no headers are added."),

	/* ssl related options */
	AP_INIT_TAKE1("CASValidateServer", cfg_readCASParameter, (void *) cmd_validate_server, RSRC_CONF, "Require validation of CAS server SSL certificate for successful authentication (On or Off)"),
	AP_INIT_TAKE1("CASValidateDepth", cfg_readCASParameter, (void *) cmd_validate_depth, RSRC_CONF, "Define the number of chained certificates required for a successful validation"),
	AP_INIT_TAKE1("CASAllowWildcardCert", cfg_readCASParameter, (void *) cmd_wildcard_cert, RSRC_CONF, "Allow wildcards in certificates when performing validation (e.g. *.example.com) (On or Off)"),
	AP_INIT_TAKE1("CASCertificatePath", cfg_readCASParameter, (void *) cmd_ca_path, RSRC_CONF, "Path to the X509 certificate for the CASServer Certificate Authority"),

	/* pertinent CAS urls */
	AP_INIT_TAKE1("CASLoginURL", cfg_readCASParameter, (void *) cmd_loginurl, RSRC_CONF, "Define the CAS Login URL (ex: https://login.example.com/cas/login)"),
	AP_INIT_TAKE1("CASValidateURL", cfg_readCASParameter, (void *) cmd_validateurl, RSRC_CONF, "Define the CAS Ticket Validation URL (ex: https://login.example.com/cas/serviceValidate)"),
	AP_INIT_TAKE1("CASProxyValidateURL", cfg_readCASParameter, (void *) cmd_proxyurl, RSRC_CONF, "Define the CAS Proxy Ticket validation URL relative to CASServer (unimplemented)"),
	AP_INIT_TAKE1("CASTicketsURL", cfg_readCASParameter, (void *) cmd_ticketsurl, RSRC_CONF, "Define the CAS REST Tickets URL (ex: https://login.example.com/cas/tickets)"),

	/* cache options */
	AP_INIT_TAKE1("CASCookiePath", cfg_readCASParameter, (void *) cmd_cookie_path, RSRC_CONF, "Path to store the CAS session cookies in (must end in trailing /)"),
	AP_INIT_TAKE1("CASCookieEntropy", cfg_readCASParameter, (void *) cmd_cookie_entropy, RSRC_CONF, "Number of random bytes to use when generating a session cookie (larger values may result in slow cookie generation)"),
	AP_INIT_TAKE1("CASCookieDomain", cfg_readCASParameter, (void *) cmd_cookie_domain, RSRC_CONF, "Specify domain header for mod_auth_cas cookie"),
	AP_INIT_TAKE1("CASCookieHttpOnly", cfg_readCASParameter, (void *) cmd_cookie_httponly, RSRC_CONF, "Enable 'HttpOnly' flag for mod_auth_cas cookie (may break RFC compliance)"),
	AP_INIT_TAKE1("CASCookie", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASCookie), ACCESS_CONF|OR_AUTHCFG, "Define the cookie name for HTTP sessions"),
	AP_INIT_TAKE1("CASSecureCookie", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASSecureCookie), ACCESS_CONF|OR_AUTHCFG, "Define the cookie name for HTTPS sessions"),
	AP_INIT_TAKE1("CASGatewayCookie", ap_set_string_slot, (void *) APR_OFFSETOF(cas_dir_cfg, CASGatewayCookie), ACCESS_CONF|OR_AUTHCFG, "Define the cookie name for a gateway location"),
	/* cache timeout options */
	AP_INIT_TAKE1("CASTimeout", cfg_readCASParameter, (void *) cmd_session_timeout, RSRC_CONF, "Maximum time (in seconds) a session cookie is valid for, regardless of idle time"),
	AP_INIT_TAKE1("CASIdleTimeout", cfg_readCASParameter, (void *) cmd_idle_timeout, RSRC_CONF, "Maximum time (in seconds) a session can be idle for"),
	AP_INIT_TAKE1("CASCacheCleanInterval", cfg_readCASParameter, (void *) cmd_cache_interval, RSRC_CONF, "Amount of time (in seconds) between cache cleanups.  This value is checked when a new local ticket is issued or when a ticket expires."),
	AP_INIT_TAKE1("CASRootProxiedAs", cfg_readCASParameter, (void *) cmd_root_proxied_as, RSRC_CONF, "URL used to access the root of the virtual server (only needed when the server is proxied)"),
	AP_INIT_FLAG("CASUserAuthoritative", ap_set_flag_slot, (void *)APR_OFFSETOF(cas_dir_cfg, authoritative), OR_AUTHCFG, "Set to 'Off' to allow access control to be passed along to lower modules if the 'require' statements are not met. (default: On)."),
	AP_INIT_TAKE1("CASAuthType", cfg_readCASParameter, (void *) cmd_CAS_authtype, OR_ALL, "Set to 'Basic' to use HTTP Basic authentication rather than redirecting to the CAS login page. Set to 'CAS' to redirect to CAS. Set to 'Both' to use the AuthType setting."),
	/* auth files (password and group file) */
	AP_INIT_TAKE1("AuthUserFile", ap_set_file_slot, (void *)APR_OFFSETOF(cas_dir_cfg, pwfile), OR_AUTHCFG, "text file containing user IDs and passwords"),
    AP_INIT_TAKE1("AuthGroupFile", ap_set_file_slot, (void *)APR_OFFSETOF(cas_dir_cfg, gpfile), OR_AUTHCFG, "text file containing group names and member user IDs"),
	{NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA auth_cas_module = {
    STANDARD20_MODULE_STUFF, 
    cas_create_dir_config,                  /* create per-dir    config structures */
    cas_merge_dir_config,                  /* merge  per-dir    config structures */
    cas_create_server_config,                  /* create per-server config structures */
    cas_merge_server_config,                  /* merge  per-server config structures */
    cas_cmds,                  /* table of config file commands       */
    cas_register_hooks  /* register hooks                      */
};
