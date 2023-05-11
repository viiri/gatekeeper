/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	yaml "gopkg.in/yaml.v2"
)

const (
	GrantTypeAuthCode     = "authorization_code"
	GrantTypeUserCreds    = "password"
	GrantTypeRefreshToken = "refresh_token"
	GrantTypeClientCreds  = "client_credentials"
	GrantTypeUmaTicket    = "urn:ietf:params:oauth:grant-type:uma-ticket"
)

// Config is the configuration for the proxy
type Config struct {
	// ConfigFile is the binding interface
	ConfigFile string `json:"config" yaml:"config" usage:"path the a configuration file" env:"CONFIG_FILE"`
	// Listen defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value.
	Listen string `json:"listen" yaml:"listen" usage:"Defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value" env:"LISTEN"`
	// ListenHTTP is the interface to bind the http only service on
	ListenHTTP string `json:"listen-http" yaml:"listen-http" usage:"interface we should be listening to for HTTP traffic" env:"LISTEN_HTTP"`
	// ListenAdmin defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen.
	ListenAdmin string `json:"listen-admin" yaml:"listen-admin" usage:"defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen" env:"LISTEN_ADMIN"`
	// ListenAdminScheme defines the scheme admin endpoints are served with. If not defined, same as main listener.
	ListenAdminScheme string `json:"listen-admin-scheme" yaml:"listen-admin-scheme" usage:"scheme to serve admin-only endpoint (http or https)." env:"LISTEN_ADMIN_SCHEME"`
	// DiscoveryURL is the url for the keycloak server
	DiscoveryURL string `json:"discovery-url" yaml:"discovery-url" usage:"discovery url to retrieve the openid configuration" env:"DISCOVERY_URL"`
	// IssuerURL is the url for issuer validation
	IssuerURL string `json:"issuer-url" yaml:"issuer-url" usage:"issuer url for issuer validation" env:"ISSUER_URL"`
	// ClientID is the client id
	ClientID string `json:"client-id" yaml:"client-id" usage:"client id used to authenticate to the oauth service" env:"CLIENT_ID"`
	// ClientSecret is the secret for AS
	ClientSecret string `json:"client-secret" yaml:"client-secret" usage:"client secret used to authenticate to the oauth service" env:"CLIENT_SECRET"`
	// RedirectionURL the redirection url
	RedirectionURL string `json:"redirection-url" yaml:"redirection-url" usage:"redirection url for the oauth callback url, defaults to host header if absent" env:"REDIRECTION_URL"`
	// PostLogoutRedirectUri the url to which is redirected after logout
	PostLogoutRedirectURI string `json:"post-logout-redirect-uri" yaml:"post-logout-redirect-uri" usage:"url to which client is redirected after successful logout" env:"POST_LOGOUT_REDIRECT_URI"`
	// RevocationEndpoint is the token revocation endpoint to revoke refresh tokens
	RevocationEndpoint string `json:"revocation-url" yaml:"revocation-url" usage:"url for the revocation endpoint to revoke refresh token" env:"REVOCATION_URL"`
	// SkipOpenIDProviderTLSVerify skips the tls verification for openid provider communication
	SkipOpenIDProviderTLSVerify bool `json:"skip-openid-provider-tls-verify" yaml:"skip-openid-provider-tls-verify" usage:"skip the verification of any TLS communication with the openid provider" env:"SKIP_OPENID_PROVIDER_TLSVERIFY"`
	// OpenIDProviderProxy proxy for openid provider communication
	OpenIDProviderProxy string `json:"openid-provider-proxy" yaml:"openid-provider-proxy" usage:"proxy for communication with the openid provider" env:"OPENID_PROVIDER_PROXY"`
	// OpenIDProviderTimeout is the timeout used to pulling the openid configuration from the provider
	OpenIDProviderTimeout time.Duration `json:"openid-provider-timeout" yaml:"openid-provider-timeout" usage:"timeout for openid configuration on .well-known/openid-configuration" env:"OPENID_PROVIDER_TIMEOUT"`
	// BaseURI is prepended to all the generated URIs
	BaseURI string `json:"base-uri" yaml:"base-uri" usage:"common prefix for all URIs" env:"BASE_URI"`
	// OAuthURI is the uri for the oauth endpoints for the proxy
	OAuthURI string `json:"oauth-uri" yaml:"oauth-uri" usage:"the uri for proxy oauth endpoints" env:"OAUTH_URI"`
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" yaml:"scopes" usage:"list of scopes requested when authenticating the user"`
	// Upstream is the upstream endpoint i.e whom were proxying to
	Upstream string `json:"upstream-url" yaml:"upstream-url" usage:"url for the upstream endpoint you wish to proxy" env:"UPSTREAM_URL"`
	// UpstreamCA is the path to a CA certificate in PEM format to validate the upstream certificate
	UpstreamCA string `json:"upstream-ca" yaml:"upstream-ca" usage:"the path to a file container a CA certificate to validate the upstream tls endpoint" env:"UPSTREAM_CA"`
	// Resources is a list of protected resources
	Resources []*authorization.Resource `json:"resources" yaml:"resources" usage:"list of resources 'uri=/admin*|methods=GET,PUT|roles=role1,role2'"`
	// Headers permits adding customs headers across the board
	Headers map[string]string `json:"headers" yaml:"headers" usage:"custom headers to the upstream request, key=value"`
	// PreserveHost preserves the host header of the proxied request in the upstream request
	PreserveHost bool `json:"preserve-host" yaml:"preserve-host" usage:"preserve the host header of the proxied request in the upstream request" env:"PRESERVE_HOST"`
	// RequestIDHeader is the header name for request ids
	RequestIDHeader string `json:"request-id-header" yaml:"request-id-header" usage:"the http header name for request id" env:"REQUEST_ID_HEADER"`
	// ResponseHeader is a map of response headers to add to the response
	ResponseHeaders map[string]string `json:"response-headers" yaml:"response-headers" usage:"custom headers to added to the http response key=value"`
	// CustomHTTPMethods is a list of additional non-standard http methods. If additional method is required it has to explicitly allowed at resource allowed method definition.
	CustomHTTPMethods []string `json:"custom-http-methods" yaml:"custom-http-methods" usage:"list of additional non-standard http methods"`

	// EnableSelfSignedTLS indicates we should create a self-signed ceritificate for the service
	EnabledSelfSignedTLS bool `json:"enable-self-signed-tls" yaml:"enable-self-signed-tls" usage:"create self signed certificates for the proxy" env:"ENABLE_SELF_SIGNED_TLS"`
	// SelfSignedTLSHostnames is the list of hostnames to place on the certificate
	SelfSignedTLSHostnames []string `json:"self-signed-tls-hostnames" yaml:"self-signed-tls-hostnames" usage:"a list of hostnames to place on the self-signed certificate"`
	// SelfSignedTLSExpiration is the expiration time of the tls certificate before rotation occurs
	SelfSignedTLSExpiration time.Duration `json:"self-signed-tls-expiration" yaml:"self-signed-tls-expiration" usage:"the expiration of the certificate before rotation" env:"SELF_SIGNED_TLS_EXPIRATION"`

	// EnableRequestID indicates the proxy should add request id if none if found
	EnableRequestID bool `json:"enable-request-id" yaml:"enable-request-id" usage:"indicates we should add a request id if none found" env:"ENABLE_REQUEST_ID"`
	// EnableLogoutRedirect indicates we should redirect to the identity provider for logging out
	EnableLogoutRedirect bool `json:"enable-logout-redirect" yaml:"enable-logout-redirect" usage:"indicates we should redirect to the identity provider for logging out" env:"ENABLE_LOGOUT_REDIRECT"`
	// EnableDefaultDeny indicates we should deny by default all unauthenticated requests
	EnableDefaultDeny bool `json:"enable-default-deny" yaml:"enable-default-deny" usage:"enables a default denial on all unauthenticated requests, you have to explicitly say what is permitted, although be aware that it allows any valid token" env:"ENABLE_DEFAULT_DENY"`
	// EnableDefaultDenyStrict indicates we should deny by default all requests
	EnableDefaultDenyStrict bool `json:"enable-default-deny-strict" yaml:"enable-default-deny-strict" usage:"enables a default denial on all requests, even valid token is denied unless you create some resources" env:"ENABLE_DEFAULT_DENY_STRICT"`
	// EnableEncryptedToken indicates the access token should be encoded
	EnableEncryptedToken bool `json:"enable-encrypted-token" yaml:"enable-encrypted-token" usage:"enable encryption for the access tokens" env:"ENABLE_ENCRYPTED_TOKEN"`
	// ForceEncryptedCookie indicates that the access token in the cookie should be encoded, regardless what EnableEncryptedToken says. This way, Louketo Proxy may receive tokens in header in the clear, whereas tokens in cookies remain encrypted
	ForceEncryptedCookie bool `json:"force-encrypted-cookie" yaml:"force-encrypted-cookie" usage:"force encryption for the access tokens in cookies" env:"FORCE_ENCRYPTED_COOKIE"`
	// EnableLogging indicates if we should log all the requests
	EnableLogging bool `json:"enable-logging" yaml:"enable-logging" usage:"enable http logging of the requests" env:"ENABLE_LOGGING"`
	// EnableJSONLogging is the logging format
	EnableJSONLogging bool `json:"enable-json-logging" yaml:"enable-json-logging" usage:"switch on json logging rather than text" env:"ENABLE_JSON_LOGGING"`
	// EnableForwarding enables the forwarding proxy
	EnableForwarding bool `json:"enable-forwarding" yaml:"enable-forwarding" usage:"enables the forwarding proxy mode, signing outbound request" env:"ENABLE_FORWARDING"`
	// EnableSecurityFilter enabled the security handler
	EnableSecurityFilter bool `json:"enable-security-filter" yaml:"enable-security-filter" usage:"enables the security filter handler" env:"ENABLE_SECURITY_FILTER"`
	// EnableRefreshTokens indicate's you wish to ignore using refresh tokens and re-auth on expiration of access token
	EnableRefreshTokens bool `json:"enable-refresh-tokens" yaml:"enable-refresh-tokens" usage:"enables the handling of the refresh tokens" env:"ENABLE_REFRESH_TOKEN"`
	// EnableSessionCookies indicates the cookies, both token and refresh should not be persisted
	EnableSessionCookies bool `json:"enable-session-cookies" yaml:"enable-session-cookies" usage:"access and refresh tokens are session only i.e. removed browser close" env:"ENABLE_SESSION_COOKIES"`
	// EnableLoginHandler indicates we want the login handler enabled
	EnableLoginHandler bool `json:"enable-login-handler" yaml:"enable-login-handler" usage:"enables the handling of the refresh tokens" env:"ENABLE_LOGIN_HANDLER"`
	// EnableTokenHeader adds the JWT token to the upstream authentication headers
	EnableTokenHeader bool `json:"enable-token-header" yaml:"enable-token-header" usage:"enables the token authentication header X-Auth-Token to upstream" env:"ENABLE_TOKEN_HEADER"`
	// EnableAuthorizationHeader indicates we should pass the authorization header to the upstream endpoint
	EnableAuthorizationHeader bool `json:"enable-authorization-header" yaml:"enable-authorization-header" usage:"adds the authorization header to the proxy request" env:"ENABLE_AUTHORIZATION_HEADER"`
	// EnableAuthorizationCookies indicates we should pass the authorization cookies to the upstream endpoint
	EnableAuthorizationCookies bool `json:"enable-authorization-cookies" yaml:"enable-authorization-cookies" usage:"adds the authorization cookies to the uptream proxy request" env:"ENABLE_AUTHORIZATION_COOKIES"`
	// EnableHTTPSRedirect indicate we should redirection http -> https
	EnableHTTPSRedirect bool `json:"enable-https-redirection" yaml:"enable-https-redirection" usage:"enable the http to https redirection on the http service" env:"ENABLE_HTTPS_REDIRECT"`
	// EnableProfiling indicates if profiles is switched on
	EnableProfiling bool `json:"enable-profiling" yaml:"enable-profiling" usage:"switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc" env:"ENABLE_PROFILING"`
	// EnableMetrics indicates if the metrics is enabled
	EnableMetrics bool `json:"enable-metrics" yaml:"enable-metrics" usage:"enable the prometheus metrics collector on /oauth/metrics" env:"ENABLE_METRICS"`
	// EnableBrowserXSSFilter indicates you want the filter on
	EnableBrowserXSSFilter bool `json:"filter-browser-xss" yaml:"filter-browser-xss" usage:"enable the adds the X-XSS-Protection header with mode=block" env:"ENABLE_BROWSER_XSS_FILTER"`
	// EnableContentNoSniff indicates you want the filter on
	EnableContentNoSniff bool `json:"filter-content-nosniff" yaml:"filter-content-nosniff" usage:"adds the X-Content-Type-Options header with the value nosniff" env:"ENABLE_CONTENT_NO_SNIFF"`
	// EnableFrameDeny indicates the filter is on
	EnableFrameDeny bool `json:"filter-frame-deny" yaml:"filter-frame-deny" usage:"enable to the frame deny header" env:"ENABLE_FRAME_DENY"`
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value
	ContentSecurityPolicy string `json:"content-security-policy" yaml:"content-security-policy" usage:"specify the content security policy" env:"CONTENT_SECURITY_POLICY"`
	// LocalhostMetrics indicates that metrics can only be consumed from localhost
	LocalhostMetrics bool `json:"localhost-metrics" yaml:"localhost-metrics" usage:"enforces the metrics page can only been requested from 127.0.0.1" env:"LOCALHOST_METRICS"`
	// EnableCompression enables gzip compression for response
	EnableCompression bool `json:"enable-compression" yaml:"enable-compression" usage:"enable gzip compression for response" env:"ENABLE_COMPRESSION"`
	// EnablePKCE, only S256 code challenge method is supported
	EnablePKCE bool `json:"enable-pkce" yaml:"enable-pkce" usage:"enable pkce for auth code flow, only S256 code challenge supported" env:"ENABLE_PKCE"`

	EnableUma   bool          `json:"enable-uma" yaml:"enable-uma" usage:"enable uma authorization, please don't use it in production, we would like to receive feedback" env:"ENABLE_UMA"`
	EnableOpa   bool          `json:"enable-opa" yaml:"enable-opa" usage:"enable authorization with external Open policy agent" env:"ENABLE_OPA"`
	OpaTimeout  time.Duration `json:"opa-timeout" yaml:"opa-timeout" usage:"timeout for connection to OPA" env:"OPA_TIMEOUT"`
	OpaAuthzURI string        `json:"opa-authz-uri" yaml:"opa-authz-uri" usage:"OPA endpoint address with path" env:"OPA_AUTHZ_URI"`

	PatRetryCount    int           `json:"pat-retry-count" yaml:"pat-retry-count" usage:"number of retries to get PAT" env:"PAT_RETRY_COUNT"`
	PatRetryInterval time.Duration `json:"pat-retry-interval" yaml:"pat-retry-interval" usage:"interval between retries to get PAT" env:"PAT_RETRY_INTERVAL"`

	// AccessTokenDuration is default duration applied to the access token cookie
	AccessTokenDuration time.Duration `json:"access-token-duration" yaml:"access-token-duration" usage:"fallback cookie duration for the access token when using refresh tokens" env:"ACCESS_TOKEN_DURATION"`
	// CookieDomain is a list of domains the cookie is available to
	CookieDomain string `json:"cookie-domain" yaml:"cookie-domain" usage:"domain the access cookie is available to, defaults host header" env:"COOKIE_DOMAIN"`
	// CookieAccessName is the name of the access cookie holding the access token
	CookieAccessName string `json:"cookie-access-name" yaml:"cookie-access-name" usage:"name of the cookie used to hold the access token" env:"COOKIE_ACCESS_NAME"`
	// CookieIdName is the name of the id token cookie holding the id token
	CookieIDTokenName string `json:"cookie-id-token-name" yaml:"cookie-id-token-name" usage:"name of the cookie used to hold id token" env:"COOKIE_ID_TOKEN_NAME"`
	// CookieRefreshName is the name of the refresh cookie
	CookieRefreshName string `json:"cookie-refresh-name" yaml:"cookie-refresh-name" usage:"name of the cookie used to hold the encrypted refresh token" env:"COOKIE_REFRESH_NAME"`
	// CookieOAuthStateName is the name of the Oauth Token request state
	CookieOAuthStateName string `json:"cookie-oauth-state-name" yaml:"cookie-oauth-state-name" usage:"name of the cookie used to hold the Oauth request state" env:"COOKIE_OAUTH_STATE_NAME"`
	// CookieRequestURIName is the name of the Request Uri cookie
	CookieRequestURIName string `json:"cookie-request-uri-name" yaml:"cookie-request-uri-name" usage:"name of the cookie used to hold the request uri" env:"COOKIE_REQUEST_URI_NAME"`
	// CookiePKCEName is the name of PKCE code verifier cookie
	CookiePKCEName string `json:"cookie-pkce-name" yaml:"cookie-pkce-name" usage:"name of the cookie used to hold PKCE code verifier" env:"COOKIE_PKCE_NAME"`
	// SecureCookie enforces the cookie as secure
	SecureCookie bool `json:"secure-cookie" yaml:"secure-cookie" usage:"enforces the cookie to be secure" env:"SECURE_COOKIE"`
	// HTTPOnlyCookie enforces the cookie as http only
	HTTPOnlyCookie bool `json:"http-only-cookie" yaml:"http-only-cookie" usage:"enforces the cookie is in http only mode" env:"HTTP_ONLY_COOKIE"`
	// SameSiteCookie enforces cookies to be send only to same site requests.
	SameSiteCookie string `json:"same-site-cookie" yaml:"same-site-cookie" usage:"enforces cookies to be send only to same site requests according to the policy (can be Strict|Lax|None)" env:"SAME_SITE_COOKIE"`

	// MatchClaims is a series of checks, the claims in the token must match those here
	MatchClaims map[string]string `json:"match-claims" yaml:"match-claims" usage:"keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*"`
	// AddClaims is a series of claims that should be added to the auth headers
	AddClaims []string `json:"add-claims" yaml:"add-claims" usage:"extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name"`

	// TLSCertificate is the location for a tls certificate
	TLSCertificate string `json:"tls-cert" yaml:"tls-cert" usage:"path to ths TLS certificate" env:"TLS_CERTIFICATE"`
	// TLSPrivateKey is the location of a tls private key
	TLSPrivateKey string `json:"tls-private-key" yaml:"tls-private-key" usage:"path to the private key for TLS" env:"TLS_PRIVATE_KEY"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSCaCertificate string `json:"tls-ca-certificate" yaml:"tls-ca-certificate" usage:"path to the ca certificate used for signing requests" env:"TLS_CA_CERTIFICATE"`
	// TLSCaPrivateKey is the CA private key used for signing
	TLSCaPrivateKey string `json:"tls-ca-key" yaml:"tls-ca-key" usage:"path the ca private key, used by the forward signing proxy" env:"TLS_CA_PRIVATE_KEY"`
	// TLSClientCertificate is path to a client certificate to use for outbound connections
	TLSClientCertificate string `json:"tls-client-certificate" yaml:"tls-client-certificate" usage:"path to the client certificate for outbound connections in reverse and forwarding proxy modes" env:"TLS_CLIENT_CERTIFICATE"`
	// SkipUpstreamTLSVerify skips the verification of any upstream tls
	SkipUpstreamTLSVerify bool `json:"skip-upstream-tls-verify" yaml:"skip-upstream-tls-verify" usage:"skip the verification of any upstream TLS" env:"SKIP_UPSTREAM_TLS_VERIFY"`
	// TLSMinVersion specifies server minimal TLS version
	TLSMinVersion string `json:"tls-min-version" yaml:"tls-min-version" usage:"specify server minimal TLS version one of tlsv1.0,tlsv1.1,tlsv1.2,tlsv1.3" env:"TLS_MIN_VERSION"`

	// TLSAdminCertificate is the location for a tls certificate for admin https endpoint. Defaults to TLSCertificate.
	TLSAdminCertificate string `json:"tls-admin-cert" yaml:"tls-admin-cert" usage:"path to ths TLS certificate" env:"TLS_ADMIN_CERTIFICATE"`
	// TLSAdminPrivateKey is the location of a tls private key for admin https endpoint. Default to TLSPrivateKey
	TLSAdminPrivateKey string `json:"tls-admin-private-key" yaml:"tls-admin-private-key" usage:"path to the private key for TLS" env:"TLS_ADMIN_PRIVATE_KEY"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSAdminCaCertificate string `json:"tls-admin-ca-certificate" yaml:"tls-admin-ca-certificate" usage:"path to the ca certificate used for signing requests" env:"TLS_ADMIN_CA_CERTIFICATE"`
	// TLSAdinClientCertificate is path to a client certificate to use for outbound connections
	TLSAdminClientCertificate string `json:"tls-admin-client-certificate" yaml:"tls-admin-client-certificate" usage:"path to the client certificate for outbound connections in reverse and forwarding proxy modes" env:"TLS_ADMIN_CLIENT_CERTIFICATE"`

	// CorsOrigins is a list of origins permitted
	CorsOrigins []string `json:"cors-origins" yaml:"cors-origins" usage:"origins to add to the CORE origins control (Access-Control-Allow-Origin)"`
	// CorsMethods is a set of access control methods
	CorsMethods []string `json:"cors-methods" yaml:"cors-methods" usage:"methods permitted in the access control (Access-Control-Allow-Methods)"`
	// CorsHeaders is a set of cors headers
	CorsHeaders []string `json:"cors-headers" yaml:"cors-headers" usage:"set of headers to add to the CORS access control (Access-Control-Allow-Headers)"`
	// CorsExposedHeaders are the exposed header fields
	CorsExposedHeaders []string `json:"cors-exposed-headers" yaml:"cors-exposed-headers" usage:"expose cors headers access control (Access-Control-Expose-Headers)"`
	// CorsCredentials set the credentials flag
	CorsCredentials bool `json:"cors-credentials" yaml:"cors-credentials" usage:"credentials access control header (Access-Control-Allow-Credentials)" env:"CORS_CREDENTIALS"`
	// CorsMaxAge is the age for CORS
	CorsMaxAge time.Duration `json:"cors-max-age" yaml:"cors-max-age" usage:"max age applied to cors headers (Access-Control-Max-Age)" env:"CORS_MAX_AGE"`
	// Hostnames is a list of hostname's the service should response to
	Hostnames []string `json:"hostnames" yaml:"hostnames" usage:"list of hostnames the service will respond to"`

	// Store is a url for a store resource, used to hold the refresh tokens
	StoreURL string `json:"store-url" yaml:"store-url" usage:"url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file" env:"STORE_URL"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption-key" yaml:"encryption-key" usage:"encryption key used to encryption the session state" env:"ENCRYPTION_KEY"`

	// NoProxy it passed through all middleware but not proxy to upstream, useful when using as auth backend for forward-auth (nginx, traefik)
	NoProxy bool `json:"no-proxy" yaml:"no-proxy" usage:"do not proxy requests to upstream, useful for forward-auth usage (with nginx, traefik)" env:"NO_PROXY"`
	// NoRedirects informs we should hand back a 401 not a redirect
	NoRedirects bool `json:"no-redirects" yaml:"no-redirects" usage:"do not have back redirects when no authentication is present, 401 them" env:"NO_REDIRECTS"`
	// SkipTokenVerification tells the service to skip verifying the access token - for testing purposes
	SkipTokenVerification bool `json:"skip-token-verification" yaml:"skip-token-verification" usage:"TESTING ONLY; bypass token verification, only expiration and roles enforced" env:"SKIP_TOKEN_VERIFICATION"`
	// according RFC issuer should not be checked on access token, this will be default true in future
	SkipAccessTokenIssuerCheck bool `json:"skip-access-token-issuer-check" yaml:"skip-access-token-issuer-check" usage:"according RFC issuer should not be checked on access token, this will be default true in future" env:"SKIP_ACCESS_TOKEN_ISSUER_CHECK"`
	// according RFC client id should not be checked on access token, this will be default true in future
	SkipAccessTokenClientIDCheck bool `json:"skip-access-token-clientid-check" yaml:"skip-access-token-clientid-check" usage:"according RFC client id should not be checked on access token, this will be default true in future" env:"SKIP_ACCESS_TOKEN_CLIENT_ID_CHECK"`
	// skip authorization header (e.g. if authorization header is used by application behind gatekeeper)
	SkipAuthorizationHeaderIdentity bool `json:"skip-authorization-header-identity" yaml:"skip-authorization-header-identity" usage:"skip authorization header identity, means that we won't be extracting token from authorization header (e.g. if authorization header is used only by application behind gatekeeper)" env:"SKIP_AUTHORIZATION_HEADER_IDENTITY"`
	// UpstreamKeepalives specifies whether we use keepalives on the upstream
	UpstreamKeepalives bool `json:"upstream-keepalives" yaml:"upstream-keepalives" usage:"enables or disables the keepalive connections for upstream endpoint" env:"UPSTREAM_KEEPALIVES"`
	// UpstreamTimeout is the maximum amount of time a dial will wait for a connect to complete
	UpstreamTimeout time.Duration `json:"upstream-timeout" yaml:"upstream-timeout" usage:"maximum amount of time a dial will wait for a connect to complete" env:"UPSTREAM_TIMEOUT"`
	// UpstreamKeepaliveTimeout is the upstream keepalive timeout
	UpstreamKeepaliveTimeout time.Duration `json:"upstream-keepalive-timeout" yaml:"upstream-keepalive-timeout" usage:"specifies the keep-alive period for an active network connection" env:"UPSTREAM_KEEPALIVE_TIMEOUT"`
	// UpstreamTLSHandshakeTimeout is the timeout for upstream to tls handshake
	UpstreamTLSHandshakeTimeout time.Duration `json:"upstream-tls-handshake-timeout" yaml:"upstream-tls-handshake-timeout" usage:"the timeout placed on the tls handshake for upstream" env:"UPSTREAM_TLS_HANDSHAKE_TIMEOUT"`
	// UpstreamResponseHeaderTimeout is the timeout for upstream header response
	UpstreamResponseHeaderTimeout time.Duration `json:"upstream-response-header-timeout" yaml:"upstream-response-header-timeout" usage:"the timeout placed on the response header for upstream" env:"UPSTREAM_RESPONSE_HEADER_TIMEOUT"`
	// UpstreamExpectContinueTimeout is the timeout expect continue for upstream
	UpstreamExpectContinueTimeout time.Duration `json:"upstream-expect-continue-timeout" yaml:"upstream-expect-continue-timeout" usage:"the timeout placed on the expect continue for upstream" env:"UPSTREAM_EXPECT_CONTINUE_TIMEOUT"`

	// Verbose switches on debug logging
	Verbose bool `json:"verbose" yaml:"verbose" usage:"switch on debug / verbose logging" env:"VERBOSE"`
	// EnableProxyProtocol controls the proxy protocol
	EnableProxyProtocol bool `json:"enabled-proxy-protocol" yaml:"enabled-proxy-protocol" usage:"enable proxy protocol" env:"ENABLE_PROXY_PROTOCOL"`

	// MaxIdleConns is the max idle connections to keep alive, ready for reuse
	MaxIdleConns int `json:"max-idle-connections" yaml:"max-idle-connections" usage:"max idle upstream / keycloak connections to keep alive, ready for reuse" env:"MAX_IDLE_CONNS"`
	// MaxIdleConnsPerHost limits the number of idle connections maintained per host
	MaxIdleConnsPerHost int `json:"max-idle-connections-per-host" yaml:"max-idle-connections-per-host" usage:"limits the number of idle connections maintained per host" env:"MAX_IDLE_CONNS_PER_HOST"`

	// ServerReadTimeout is the read timeout on the http server
	ServerReadTimeout time.Duration `json:"server-read-timeout" yaml:"server-read-timeout" usage:"the server read timeout on the http server" env:"SERVER_READ_TIMEOUT"`
	// ServerWriteTimeout is the write timeout on the http server
	ServerWriteTimeout time.Duration `json:"server-write-timeout" yaml:"server-write-timeout" usage:"the server write timeout on the http server" env:"SERVER_WRITE_TIMEOUT"`
	// ServerIdleTimeout is the idle timeout on the http server
	ServerIdleTimeout time.Duration `json:"server-idle-timeout" yaml:"server-idle-timeout" usage:"the server idle timeout on the http server" env:"SERVER_IDLE_TIMEOUT"`

	// UseLetsEncrypt controls if we should use letsencrypt to retrieve certificates
	UseLetsEncrypt bool `json:"use-letsencrypt" yaml:"use-letsencrypt" usage:"use letsencrypt for certificates" env:"USE_LETS_ENCRYPT"`

	// LetsEncryptCacheDir is the path to store letsencrypt certificates
	LetsEncryptCacheDir string `json:"letsencrypt-cache-dir" yaml:"letsencrypt-cache-dir" usage:"path where cached letsencrypt certificates are stored" env:"LETS_ENCRYPT_CACHE_DIR"`

	// SignInPage is the relative url for the sign in page
	SignInPage string `json:"sign-in-page" yaml:"sign-in-page" usage:"path to custom template displayed for signin" env:"SIGN_IN_PAGE"`
	// ForbiddenPage is a access forbidden page
	ForbiddenPage string `json:"forbidden-page" yaml:"forbidden-page" usage:"path to custom template used for access forbidden" env:"FORBIDDEN_PAGE"`
	// ErrorPage is the relative url for the custom error page
	ErrorPage string `json:"error-page" yaml:"error-page" usage:"path to custom template displayed for http.StatusBadRequest" env:"ERROR_PAGE"`
	// Tags is passed to the templates
	Tags map[string]string `json:"tags" yaml:"tags" usage:"keypairs passed to the templates at render,e.g title=Page"`

	ForwardingGrantType string `json:"forwarding-grant-type" yaml:"forwarding-grant-type" usage:"grant-type to use when logging into the openid provider, can be one of password, client_credentials" env:"FORWARDING_GRANT_TYPE"`
	// ForwardingUsername is the username to login to the oauth service
	ForwardingUsername string `json:"forwarding-username" yaml:"forwarding-username" usage:"username to use when logging into the openid provider" env:"FORWARDING_USERNAME"`
	// ForwardingPassword is the password to use for the above
	ForwardingPassword string `json:"forwarding-password" yaml:"forwarding-password" usage:"password to use when logging into the openid provider" env:"FORWARDING_PASSWORD"`
	// ForwardingDomains is a collection of domains to signs
	ForwardingDomains []string `json:"forwarding-domains" yaml:"forwarding-domains" usage:"list of domains which should be signed; everything else is relayed unsigned"`

	// DisableAllLogging indicates no logging at all
	DisableAllLogging bool `json:"disable-all-logging" yaml:"disable-all-logging" usage:"disables all logging to stdout and stderr" env:"DISABLE_ALL_LOGGING"`
	// this is non-configurable field, derived from discoveryurl at initialization
	Realm               string
	DiscoveryURI        *url.URL
	OpaAuthzURL         *url.URL
	IsDiscoverURILegacy bool
}

// NewDefaultConfig returns a initialized config
func NewDefaultConfig() *Config {
	var hostnames []string
	if name, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, name)
	}
	hostnames = append(hostnames, []string{"localhost", "127.0.0.1", "::1"}...)

	return &Config{
		AccessTokenDuration:           time.Duration(720) * time.Hour,
		CookieAccessName:              constant.AccessCookie,
		CookieIDTokenName:             constant.IDTokenCookie,
		CookieRefreshName:             constant.RefreshCookie,
		CookieOAuthStateName:          constant.RequestStateCookie,
		CookieRequestURIName:          constant.RequestURICookie,
		CookiePKCEName:                constant.PKCECookie,
		EnableAuthorizationCookies:    true,
		EnableAuthorizationHeader:     true,
		EnableDefaultDeny:             true,
		EnableSessionCookies:          true,
		EnableTokenHeader:             true,
		HTTPOnlyCookie:                true,
		Headers:                       make(map[string]string),
		LetsEncryptCacheDir:           "./cache/",
		MatchClaims:                   make(map[string]string),
		MaxIdleConns:                  100,
		MaxIdleConnsPerHost:           50,
		OAuthURI:                      "/oauth",
		OpenIDProviderTimeout:         30 * time.Second,
		PreserveHost:                  false,
		SelfSignedTLSExpiration:       3 * time.Hour,
		SelfSignedTLSHostnames:        hostnames,
		RequestIDHeader:               "X-Request-ID",
		ResponseHeaders:               make(map[string]string),
		SameSiteCookie:                constant.SameSiteLax,
		Scopes:                        []string{"email", "profile"},
		SecureCookie:                  true,
		ServerIdleTimeout:             120 * time.Second,
		ServerReadTimeout:             10 * time.Second,
		ServerWriteTimeout:            10 * time.Second,
		SkipOpenIDProviderTLSVerify:   false,
		SkipUpstreamTLSVerify:         true,
		Tags:                          make(map[string]string),
		TLSMinVersion:                 "tlsv1.3",
		UpstreamExpectContinueTimeout: 10 * time.Second,
		UpstreamKeepaliveTimeout:      10 * time.Second,
		UpstreamKeepalives:            true,
		UpstreamResponseHeaderTimeout: 10 * time.Second,
		UpstreamTLSHandshakeTimeout:   10 * time.Second,
		UpstreamTimeout:               10 * time.Second,
		UseLetsEncrypt:                false,
		ForwardingGrantType:           GrantTypeUserCreds,
		PatRetryCount:                 5,
		PatRetryInterval:              10 * time.Second,
		OpaTimeout:                    10 * time.Second,
	}
}

// readConfigFile reads and parses the configuration file
func ReadConfigFile(filename string, config *Config) error {
	content, err := ioutil.ReadFile(filename)

	if err != nil {
		return err
	}
	// step: attempt to un-marshal the data
	switch ext := filepath.Ext(filename); ext {
	case "json":
		err = json.Unmarshal(content, config)
	default:
		err = yaml.Unmarshal(content, config)
	}

	return err
}

func writeFakeConfigFile(t *testing.T, content string) *os.File {
	file, err := ioutil.TempFile("", "node_label_file")
	if err != nil {
		t.Fatalf("unexpected error creating node_label_file: %v", err)
	}
	file.Close()

	if err := ioutil.WriteFile(file.Name(), []byte(content), 0600); err != nil {
		t.Fatalf("unexpected error writing node label file: %v", err)
	}

	return file
}

// WithOAuthURI returns the oauth uri
func (r *Config) WithOAuthURI(uri string) string {
	uri = strings.TrimPrefix(uri, "/")
	if r.BaseURI != "" {
		return fmt.Sprintf("%s/%s/%s", r.BaseURI, r.OAuthURI, uri)
	}

	return fmt.Sprintf("%s/%s", r.OAuthURI, uri)
}

func (r *Config) Update() error {
	updateRegistry := []func() error{
		r.updateDiscoveryURI,
		r.extractDiscoveryURIComponents,
	}

	for _, updateFunc := range updateRegistry {
		if err := updateFunc(); err != nil {
			return err
		}
	}

	return nil
}

// IsValid validates if the config is valid
func (r *Config) IsValid() error {
	if r.ListenAdmin == r.Listen {
		r.ListenAdmin = ""
	}

	if r.ListenAdminScheme == "" {
		r.ListenAdminScheme = constant.SecureScheme
	}

	validationRegistry := []func() error{
		r.isListenValid,
		r.isListenAdminSchemeValid,
		r.isOpenIDProviderProxyValid,
		r.isMaxIdlleConnValid,
		r.isSameSiteValid,
		r.isTLSFilesValid,
		r.isAdminTLSFilesValid,
		r.isLetsEncryptValid,
		r.isTLSMinValid,
		r.isForwardingProxySettingsValid,
		r.isReverseProxySettingsValid,
	}

	for _, validationFunc := range validationRegistry {
		if err := validationFunc(); err != nil {
			return err
		}
	}

	return nil
}

// HasCustomSignInPage checks if there is a custom sign in  page
func (r *Config) HasCustomSignInPage() bool {
	return r.SignInPage != ""
}

// HasForbiddenPage checks if there is a custom forbidden page
func (r *Config) HasCustomForbiddenPage() bool {
	return r.ForbiddenPage != ""
}

// HasCustomErrorPage checks if there is a custom error page
func (r *Config) HasCustomErrorPage() bool {
	return r.ErrorPage != ""
}

func (r *Config) isListenValid() error {
	if r.Listen == "" {
		return errors.New("you have not specified the listening interface")
	}
	return nil
}

func (r *Config) isListenAdminSchemeValid() error {
	if r.ListenAdminScheme != constant.SecureScheme &&
		r.ListenAdminScheme != constant.UnsecureScheme {
		return errors.New("scheme for admin listener must be one of [http, https]")
	}
	return nil
}

func (r *Config) isOpenIDProviderProxyValid() error {
	if r.OpenIDProviderProxy != "" {
		_, err := url.ParseRequestURI(r.OpenIDProviderProxy)

		if err != nil {
			return errors.New("invalid proxy address for open IDP provider proxy")
		}
	}

	return nil
}

func (r *Config) isMaxIdlleConnValid() error {
	if r.MaxIdleConns <= 0 {
		return errors.New("max-idle-connections must be a number > 0")
	}

	if r.MaxIdleConnsPerHost < 0 || r.MaxIdleConnsPerHost > r.MaxIdleConns {
		return errors.New(
			"maxi-idle-connections-per-host must be a " +
				"number > 0 and <= max-idle-connections",
		)
	}
	return nil
}

func (r *Config) isSameSiteValid() error {
	if r.SameSiteCookie != "" && r.SameSiteCookie != constant.SameSiteStrict &&
		r.SameSiteCookie != constant.SameSiteLax && r.SameSiteCookie != constant.SameSiteNone {
		return errors.New("same-site-cookie must be one of Strict|Lax|None")
	}
	return nil
}

//nolint:cyclop
func (r *Config) isTLSFilesValid() error {
	if r.TLSCertificate != "" && r.TLSPrivateKey == "" {
		return errors.New("you have not provided a private key")
	}

	if r.TLSPrivateKey != "" && r.TLSCertificate == "" {
		return errors.New("you have not provided a certificate file")
	}

	if r.TLSCertificate != "" && !utils.FileExists(r.TLSCertificate) {
		return fmt.Errorf("the tls certificate %s does not exist", r.TLSCertificate)
	}

	if r.TLSPrivateKey != "" && !utils.FileExists(r.TLSPrivateKey) {
		return fmt.Errorf("the tls private key %s does not exist", r.TLSPrivateKey)
	}

	if r.TLSCaCertificate != "" && !utils.FileExists(r.TLSCaCertificate) {
		return fmt.Errorf(
			"the tls ca certificate file %s does not exist",
			r.TLSCaCertificate,
		)
	}

	if r.TLSClientCertificate != "" && !utils.FileExists(r.TLSClientCertificate) {
		return fmt.Errorf(
			"the tls client certificate %s does not exist",
			r.TLSClientCertificate,
		)
	}

	return nil
}

//nolint:cyclop
func (r *Config) isAdminTLSFilesValid() error {
	if r.TLSAdminCertificate != "" && r.TLSAdminPrivateKey == "" {
		return errors.New("you have not provided a private key for admin endpoint")
	}

	if r.TLSAdminPrivateKey != "" && r.TLSAdminCertificate == "" {
		return errors.New(
			"you have not provided a certificate file for admin endpoint",
		)
	}

	if r.TLSAdminCertificate != "" && !utils.FileExists(r.TLSAdminCertificate) {
		return fmt.Errorf(
			"the tls certificate %s does not exist for admin endpoint",
			r.TLSAdminCertificate,
		)
	}

	if r.TLSAdminPrivateKey != "" && !utils.FileExists(r.TLSAdminPrivateKey) {
		return fmt.Errorf(
			"the tls private key %s does not exist for admin endpoint",
			r.TLSAdminPrivateKey,
		)
	}

	if r.TLSAdminCaCertificate != "" && !utils.FileExists(r.TLSAdminCaCertificate) {
		return fmt.Errorf(
			"the tls ca certificate file %s does not exist for admin endpoint",
			r.TLSAdminCaCertificate,
		)
	}

	if r.TLSAdminClientCertificate != "" && !utils.FileExists(r.TLSAdminClientCertificate) {
		return fmt.Errorf(
			"the tls client certificate %s does not exist for admin endpoint",
			r.TLSAdminClientCertificate,
		)
	}

	return nil
}

func (r *Config) isLetsEncryptValid() error {
	if r.UseLetsEncrypt && r.LetsEncryptCacheDir == "" {
		return fmt.Errorf("the letsencrypt cache dir has not been set")
	}
	return nil
}

func (r *Config) isTLSMinValid() error {
	switch strings.ToLower(r.TLSMinVersion) {
	case "":
		return fmt.Errorf("minimal TLS version should not be empty")
	case "tlsv1.0":
	case "tlsv1.1":
	case "tlsv1.2":
	case "tlsv1.3":
	default:
		return fmt.Errorf("invalid minimal TLS version specified")
	}
	return nil
}

func (r *Config) isForwardingProxySettingsValid() error {
	if r.EnableForwarding {
		validationRegistry := []func() error{
			r.isClientIDValid,
			r.isDiscoveryURLValid,
			r.isForwardingGrantValid,
			func() error {
				if r.TLSCertificate != "" {
					return errors.New("you don't need to specify a " +
						"tls-certificate, use tls-ca-certificate instead",
					)
				}
				return nil
			},
			func() error {
				if r.TLSPrivateKey != "" {
					return errors.New("you don't need to specify the " +
						"tls-private-key, use tls-ca-key instead",
					)
				}
				return nil
			},
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Config) isReverseProxySettingsValid() error {
	if !r.EnableForwarding {
		validationRegistry := []func() error{
			r.isNoProxyValid,
			r.isUpstreamValid,
			r.isDefaultDenyValid,
			r.isExternalAuthzValid,
			r.isTokenVerificationSettingsValid,
			r.isResourceValid,
			r.isMatchClaimValid,
			r.isPKCEValid,
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}

		return nil
	}

	return nil
}

func (r *Config) isTokenVerificationSettingsValid() error {
	// step: if the skip verification is off, we need the below
	if !r.SkipTokenVerification {
		validationRegistry := []func() error{
			r.isClientIDValid,
			r.isDiscoveryURLValid,
			func() error {
				r.RedirectionURL = strings.TrimSuffix(r.RedirectionURL, "/")
				return nil
			},
			r.isSecurityFilterValid,
			r.isTokenEncryptionValid,
			r.isSecureCookieValid,
			r.isStoreURLValid,
		}

		for _, validationFunc := range validationRegistry {
			if err := validationFunc(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Config) isNoProxyValid() error {
	if r.NoProxy && !r.NoRedirects && r.RedirectionURL != "" {
		return errors.New("when in forward-auth mode - " +
			"noproxy=true with noredirect=false, redirectionURL " +
			"should not be set, will be composed from X-FORWARDED-* headers",
		)
	}
	return nil
}

func (r *Config) isUpstreamValid() error {
	if r.Upstream == "" && !r.NoProxy {
		return errors.New("you have not specified an upstream endpoint to proxy to")
	}

	if !r.NoProxy {
		if _, err := url.ParseRequestURI(r.Upstream); err != nil {
			return fmt.Errorf("the upstream endpoint is invalid, %s", err)
		}
	}

	if r.SkipUpstreamTLSVerify && r.UpstreamCA != "" {
		return fmt.Errorf("you cannot skip upstream tls and load a root ca: %s to verify it", r.UpstreamCA)
	}

	return nil
}

func (r *Config) isClientIDValid() error {
	if r.ClientID == "" {
		return errors.New("you have not specified the client id")
	}
	return nil
}

func (r *Config) isDiscoveryURLValid() error {
	if r.DiscoveryURL == "" {
		return errors.New("you have not specified the discovery url")
	}

	if r.IssuerURL != "" {
		_, err := url.ParseRequestURI(r.IssuerURL)

		if err != nil {
			return errors.New("invalid issuer url")
		}
	}

	return nil
}

func (r *Config) isForwardingGrantValid() error {
	if r.ForwardingGrantType == GrantTypeUserCreds {
		if r.ForwardingUsername == "" {
			return errors.New("no forwarding username")
		}

		if r.ForwardingPassword == "" {
			return errors.New("no forwarding password")
		}
	}

	if r.ForwardingGrantType == GrantTypeClientCreds {
		if r.ClientSecret == "" {
			return errors.New("you have not specified the client secret")
		}
	}

	return nil
}

func (r *Config) isSecurityFilterValid() error {
	if !r.EnableSecurityFilter {
		if r.EnableHTTPSRedirect {
			return errors.New(
				"the security filter must be switch on for this feature: http-redirect",
			)
		}

		if r.EnableBrowserXSSFilter {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: brower-xss-filter",
			)
		}

		if r.EnableFrameDeny {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: frame-deny-filter",
			)
		}

		if r.ContentSecurityPolicy != "" {
			return errors.New(
				"the security filter must be switch on " +
					"for this feature: content-security-policy",
			)
		}

		if len(r.Hostnames) > 0 {
			return errors.New(
				"the security filter must be switch on for this feature: hostnames",
			)
		}
	}

	return nil
}

func (r *Config) isTokenEncryptionValid() error {
	if (r.EnableEncryptedToken || r.ForceEncryptedCookie) &&
		r.EncryptionKey == "" {
		return errors.New(
			"you have not specified an encryption key for encoding the access token",
		)
	}

	if r.EnableRefreshTokens && r.EncryptionKey == "" {
		return errors.New(
			"enable refresh tokens requires encryption key to be defined",
		)
	}

	if r.EnableRefreshTokens && (len(r.EncryptionKey) != 16 &&
		len(r.EncryptionKey) != 32) {
		return fmt.Errorf(
			"the encryption key (%d) must be either 16 or 32 "+
				"characters for AES-128/AES-256 selection",
			len(r.EncryptionKey),
		)
	}

	return nil
}

func (r *Config) isSecureCookieValid() error {
	if !r.NoRedirects && r.SecureCookie && r.RedirectionURL != "" &&
		!strings.HasPrefix(r.RedirectionURL, "https") {
		return errors.New(
			"the cookie is set to secure but your redirection url is non-tls",
		)
	}

	return nil
}

func (r *Config) isStoreURLValid() error {
	if r.StoreURL != "" {
		if _, err := url.ParseRequestURI(r.StoreURL); err != nil {
			return fmt.Errorf("the store url is invalid, error: %s", err)
		}
	}

	return nil
}

func (r *Config) isResourceValid() error {
	// step: add custom http methods for check
	if r.CustomHTTPMethods != nil {
		for _, customHTTPMethod := range r.CustomHTTPMethods {
			chi.RegisterMethod(customHTTPMethod)
			utils.AllHTTPMethods = append(utils.AllHTTPMethods, customHTTPMethod)
		}
	}

	// check: ensure each of the resource are valid
	for _, resource := range r.Resources {
		if err := resource.Valid(); err != nil {
			return err
		}

		if resource.URL == constant.AllPath && (r.EnableDefaultDeny || r.EnableDefaultDenyStrict) {
			switch resource.WhiteListed {
			case true:
				return apperrors.ErrDefaultDenyWhitelistConflict
			default:
				return apperrors.ErrDefaultDenyUserDefinedConflict
			}
		}
	}

	return nil
}

func (r *Config) isMatchClaimValid() error {
	// step: validate the claims are validate regex's
	for k, claim := range r.MatchClaims {
		if _, err := regexp.Compile(claim); err != nil {
			return fmt.Errorf(
				"the claim matcher: %s for claim: %s is not a valid regex",
				claim,
				k,
			)
		}
	}

	return nil
}

func (r *Config) isExternalAuthzValid() error {
	if r.EnableUma && r.EnableOpa {
		return errors.New(
			"only one type of external authz can be enabled at once",
		)
	}

	if r.EnableUma {
		if r.ClientID == "" || r.ClientSecret == "" {
			return errors.New(
				"enable uma requires client credentials",
			)
		}
		if !r.NoRedirects {
			return errors.New(
				"enable-uma requires no-redirects option",
			)
		}
	} else if r.EnableOpa {
		authzURL, err := url.ParseRequestURI(r.OpaAuthzURI)

		if err != nil {
			return fmt.Errorf("not valid OPA authz URL, %w", err)
		}

		r.OpaAuthzURL = authzURL
	}

	return nil
}

func (r *Config) isDefaultDenyValid() error {
	if r.EnableDefaultDeny && r.EnableDefaultDenyStrict {
		return errors.New(
			"only one of enable-default-deny/enable-default-deny-strict can be true",
		)
	}
	return nil
}

func (r *Config) updateDiscoveryURI() error {
	// step: fix up the url if required, the underlining lib will add
	// the .well-known/openid-configuration to the discovery url for us.
	r.DiscoveryURL = strings.TrimSuffix(
		r.DiscoveryURL,
		"/.well-known/openid-configuration",
	)

	uri, err := url.ParseRequestURI(r.DiscoveryURL)

	if err != nil {
		return fmt.Errorf(
			"failed to parse discovery url: %w",
			err,
		)
	}

	r.DiscoveryURI = uri

	return nil
}

func (r *Config) extractDiscoveryURIComponents() error {
	reg := regexp.MustCompile(
		`(?P<legacy>(/auth){0,1})/realms/(?P<realm>[^/]+)(/{0,1}).*`,
	)

	matches := reg.FindStringSubmatch(r.DiscoveryURI.Path)

	if len(matches) == 0 {
		return apperrors.ErrBadDiscoveryURIFormat
	}

	legacyIndex := reg.SubexpIndex("legacy")
	realmIndex := reg.SubexpIndex("realm")

	if matches[legacyIndex] != "" {
		r.IsDiscoverURILegacy = true
	}

	r.Realm = matches[realmIndex]
	return nil
}

func (r *Config) isPKCEValid() error {
	if r.NoRedirects && r.EnablePKCE {
		return apperrors.ErrPKCEWithCodeOnly
	}
	return nil
}
