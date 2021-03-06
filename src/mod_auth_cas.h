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
 * mod_auth_cas.h
 * Apache CAS Authentication Module
 * Version 1.0.8SFU
 *
 * Author:
 * Phil Ames       <modauthcas [at] gmail [dot] com>
 * Designers:
 * Phil Ames       <modauthcas [at] gmail [dot] com>
 * Matt Smith      <matt [dot] smith [at] uconn [dot] edu>
 * SFU Additions:
 * Ray Davison	<ray [at] sfu [dot] ca>
 */

#ifndef MOD_AUTH_CAS_H
#define MOD_AUTH_CAS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include "ap_release.h"

// @@@
#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211
#include "mod_auth.h"
#endif

// @@@
#include "cas_saml_attr.h"

#ifndef AP_SERVER_MAJORVERSION_NUMBER
	#ifndef AP_SERVER_MINORVERSION_NUMBER
		#define APACHE2_0
	#endif
#endif

#ifndef APACHE2_0
	#ifdef AP_SERVER_MAJORVERSION_NUMBER
		#ifdef AP_SERVER_MINORVERSION_NUMBER
			#if ((AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER == 0))
				#define APACHE2_0
			#endif
		#endif
	#endif
#endif

#ifdef WIN32
typedef SOCKET socket_t;
#else
typedef int socket_t;
#define INVALID_SOCKET -1
#endif

#ifdef BROKEN
#undef BROKEN
#endif

#define CAS_DEFAULT_VERSION 2
#define CAS_DEFAULT_DEBUG FALSE
#define CAS_DEFAULT_SCOPE NULL
#define CAS_DEFAULT_RENEW NULL
#define CAS_DEFAULT_GATEWAY NULL
#define CAS_DEFAULT_VALIDATE_SAML 0
#define CAS_DEFAULT_VALIDATE_SERVER 1
#define CAS_DEFAULT_VALIDATE_DEPTH 9
#define CAS_DEFAULT_ALLOW_WILDCARD_CERT 0
#define CAS_DEFAULT_CA_PATH "/etc/ssl/certs/"
#define CAS_DEFAULT_COOKIE_PATH "/dev/null"
#define CAS_DEFAULT_LOGIN_URL NULL
#define CAS_DEFAULT_VALIDATE_V1_URL NULL
#define CAS_DEFAULT_VALIDATE_V2_URL NULL
#define CAS_DEFAULT_VALIDATE_URL CAS_DEFAULT_VALIDATE_V2_URL
#define CAS_DEFAULT_PROXY_VALIDATE_URL NULL
#define CAS_DEFAULT_ROOT_PROXIED_AS_URL NULL
#define CAS_DEFAULT_TICKETS_URL NULL
#define CAS_DEFAULT_COOKIE_ENTROPY 32
#define CAS_DEFAULT_COOKIE_DOMAIN NULL
#define CAS_DEFAULT_COOKIE_HTTPONLY 0
#define CAS_DEFAULT_COOKIE_TIMEOUT 7200 /* 2 hours */
#define CAS_DEFAULT_COOKIE_IDLE_TIMEOUT 3600 /* 1 hour */
#define CAS_DEFAULT_CACHE_CLEAN_INTERVAL  1800 /* 30 minutes */
#define CAS_DEFAULT_COOKIE "MOD_AUTH_CAS"
#define CAS_DEFAULT_SCOOKIE "MOD_AUTH_CAS_S"
#define CAS_DEFAULT_GATEWAY_COOKIE "MOD_CAS_G"
#define CAS_DEFAULT_AUTHN_HEADER "CAS-User"
/*
 * The following are for the SFU extensions
 */
#define CAS_DEFAULT_AUTHTYPE NULL
#define CAS_DEFAULT_MAILLIST NULL
#define CAS_DEFAULT_PWFILE NULL
#define CAS_DEFAULT_GPFILE NULL
#define CAS_DEFAULT_AUTHORITATIVE 1
#define CAS_AUTHTYPE_BASIC 0
#define CAS_AUTHTYPE_CAS 1
#define CAS_AUTHTYPE_BOTH 2
#define CAS_DEFAULT_USEAUTHTYPE CAS_AUTHTYPE_CAS
#define CAS_DEFAULT_AUTHTYPE_HEADER "CAS-Authtype"
#define CAS_DEFAULT_MAILLIST_HEADER "CAS-Maillist"

#define CAS_MAX_RESPONSE_SIZE 65536
#define CAS_MAX_ERROR_SIZE 1024
#define CAS_MAX_XML_SIZE 1024

#define CAS_ATTR_MATCH 0
#define CAS_ATTR_NO_MATCH 1

typedef struct cas_cfg {
	unsigned int CASVersion;
	unsigned int CASDebug;
	unsigned int CASValidateServer;
	unsigned int CASValidateDepth;
	unsigned int CASAllowWildcardCert;
	unsigned int CASCacheCleanInterval;
	unsigned int CASCookieEntropy;
	unsigned int CASTimeout;
	unsigned int CASIdleTimeout;
	unsigned int CASCookieHttpOnly;
	unsigned int CASValidateSAML;
	char *CASCertificatePath;
	char *CASCookiePath;
	char *CASCookieDomain;
	char *CASAttributeDelimiter;
	char *CASAttributePrefix;
	apr_uri_t CASLoginURL;
	apr_uri_t CASValidateURL;
	apr_uri_t CASProxyValidateURL;
	apr_uri_t CASRootProxiedAs;
	apr_uri_t CASTicketsURL;
} cas_cfg;

typedef struct cas_dir_cfg {
	char *CASScope;
	char *CASRenew;
	char *CASGateway;
	char *CASCookie;
	char *CASSecureCookie;
	char *CASGatewayCookie;
	char *CASAuthNHeader;
	/* The following are SFU extensions */
	char *authtype;
	char *maillist;
	char *password; /* save the password provided for Basic authentication */
	char *pwfile;
	char *gpfile;
	int authoritative;
	int haveTicket;
	int useauthtype;
	char *CASAuthTypeHeader;
	char *CASAuthMaillistHeader;
} cas_dir_cfg;

typedef struct cas_cache_entry {
	char *user;
	apr_time_t issued;
	apr_time_t lastactive;
	char *path;
	apr_byte_t renewed;
	apr_byte_t secure;
	char *ticket;
	/* The following are for the SFU extensions */
	char *authtype;
	char *maillist;
	// @@@
	cas_saml_attr *attrs;
} cas_cache_entry;

typedef enum { 
	cmd_version, cmd_debug, cmd_validate_server, cmd_validate_depth, cmd_wildcard_cert, 
	cmd_ca_path, cmd_cookie_path, cmd_loginurl, cmd_validateurl, cmd_proxyurl, cmd_ticketsurl, cmd_cookie_entropy, 
	cmd_session_timeout, cmd_idle_timeout, cmd_cache_interval, cmd_cookie_domain, cmd_cookie_httponly, 
	cmd_validate_saml, cmd_root_proxied_as, cmd_CAS_authtype 
} valid_cmds;

module AP_MODULE_DECLARE_DATA auth_cas_module;
static apr_byte_t cas_setURL(apr_pool_t *pool, apr_uri_t *uri, const char *url);
static void *cas_create_server_config(apr_pool_t *pool, server_rec *svr);
static void *cas_create_dir_config(apr_pool_t *pool, char *path);
static void *cas_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
static const char *cfg_readCASParameter(cmd_parms *cmd, void *cfg, const char *value);
static apr_byte_t check_cert_cn(request_rec *r, cas_cfg *c, SSL_CTX *ctx, X509 *certificate, char *cn);
static void CASCleanupSocket(socket_t s, SSL *ssl, SSL_CTX *ctx);
static char *getResponseFromServer (request_rec *r, cas_cfg *c, char *ticket);

static apr_byte_t isValidCASTicket(request_rec *r, cas_cfg *c, char *ticket, char **user, cas_saml_attr **attrs, char **authtype, char **maillist);

static apr_byte_t isSSL(request_rec *r);
static apr_byte_t readCASCacheFile(request_rec *r, cas_cfg *c, char *name, cas_cache_entry *cache);
static void CASCleanCache(request_rec *r, cas_cfg *c);
static apr_byte_t isValidCASCookie(request_rec *r, cas_cfg *c, char *cookie, char **user, cas_saml_attr **attrs, char **authtype, char **maillist);
static char *getCASCookie(request_rec *r, char *cookieName);
static apr_byte_t writeCASCacheEntry(request_rec *r, char *name, cas_cache_entry *cache, apr_byte_t exists);

static char *createCASCookie(request_rec *r, char *user, cas_saml_attr *attrs, char *ticket, char *authtype, char *maillist);

static void expireCASST(request_rec *r, char *ticketname);
#ifdef BROKEN
static void CASSAMLLogout(request_rec *r, char *body);
static apr_status_t cas_in_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);
#endif
static void deleteCASCacheFile(request_rec *r, char *cookieName);
static void setCASCookie(request_rec *r, char *cookieName, char *cookieValue, apr_byte_t secure);
static char *escapeString(request_rec *r, char *str);
static char *urlEncode(request_rec *r, char *str, char *charsToEncode);
static char *getCASGateway(request_rec *r);
static char *getCASRenew(request_rec *r);
static char *getCASValidateURL(request_rec *r, cas_cfg *c);
static char *getCASLoginURL(request_rec *r, cas_cfg *c);
static char *getCASTicketsURL(request_rec *r, cas_cfg *c);
static char *getCASService(request_rec *r, cas_cfg *c);
static void redirectRequest(request_rec *r, cas_cfg *c);
static char *getCASTicket(request_rec *r);
static apr_byte_t removeCASParams(request_rec *r);
static int cas_authenticate(request_rec *r);
static int cas_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s);
static void cas_register_hooks(apr_pool_t *p);

/* Access per-request CAS SAML attributes */
void cas_set_attributes(request_rec *r, cas_saml_attr *const attrs);
const cas_saml_attr *cas_get_attributes(request_rec *r);
int cas_match_attribute(const char *const attr_spec, const cas_saml_attr *const attributes, struct request_rec *r);

/* Authorization check */
#if MODULE_MAGIC_NUMBER_MAJOR < 20120211
int cas_authorize(request_rec *r);
int cas_authorize_worker(request_rec *r, const cas_saml_attr *const attrs, const require_line *const reqs, int nelts, const cas_cfg *const c);
#else
authz_status cas_check_authorization(request_rec *r, const char *require_line, const void *parsed_require_line);
#endif

/* Fancy wrapper around flock() */
int cas_flock(apr_file_t *fileHandle, int lockOperation, request_rec *r);

/* apr forward compatibility */
#ifndef APR_FOPEN_READ
#define APR_FOPEN_READ		APR_READ
#endif

#ifndef APR_FOPEN_WRITE
#define APR_FOPEN_WRITE		APR_WRITE
#endif

#ifndef APR_FOPEN_CREATE
#define APR_FOPEN_CREATE	APR_CREATE
#endif

#ifndef APR_FPROT_UWRITE
#define APR_FPROT_UWRITE	APR_UWRITE
#endif

#ifndef APR_FPROT_UREAD
#define APR_FPROT_UREAD		APR_UREAD
#endif



#endif /* MOD_AUTH_CAS_H */
