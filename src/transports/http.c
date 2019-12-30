/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#ifndef GIT_WINHTTP

#include "git2.h"
#include "http_parser.h"
#include "buffer.h"
#include "net.h"
#include "netops.h"
#include "global.h"
#include "remote.h"
#include "git2/sys/cred.h"
#include "smart.h"
#include "auth.h"
#include "http.h"
#include "auth_negotiate.h"
#include "auth_ntlm.h"
#include "trace.h"
#include "streams/tls.h"
#include "streams/socket.h"
#include "httpclient.h"

bool git_http__expect_continue = false;

git_http_service upload_pack_ls_service = {
	GIT_HTTP_METHOD_GET, "/info/refs?service=git-upload-pack",
	NULL,
	"application/x-git-upload-pack-advertisement",
	0
};
git_http_service upload_pack_service = {
	GIT_HTTP_METHOD_POST, "/git-upload-pack",
	"application/x-git-upload-pack-request",
	"application/x-git-upload-pack-result",
	0
};
git_http_service receive_pack_ls_service = {
	GIT_HTTP_METHOD_GET, "/info/refs?service=git-receive-pack",
	NULL,
	"application/x-git-receive-pack-advertisement",
	0
};
git_http_service receive_pack_service = {
	GIT_HTTP_METHOD_POST, "/git-receive-pack",
	"application/x-git-receive-pack-request",
	"application/x-git-receive-pack-result",
	1
};

#define SERVER_TYPE_REMOTE "remote"
#define SERVER_TYPE_PROXY  "proxy"

#define OWNING_SUBTRANSPORT(s) ((http_subtransport *)(s)->parent.subtransport)

typedef enum {
	HTTP_STATE_NONE = 0,
	HTTP_STATE_SENDING_REQUEST,
	HTTP_STATE_RECEIVING_RESPONSE,
	HTTP_STATE_DONE
} http_state;

typedef struct {
	git_smart_subtransport_stream parent;
	git_http_service *service;
	http_state state;
	unsigned replay_count;
} http_stream;

typedef struct {
	git_net_url url;

	git_cred *cred;
	unsigned auth_schemetypes;
	unsigned url_cred_presented : 1;
} http_server;

typedef struct {
	git_smart_subtransport parent;
	transport_smart *owner;

	http_server server;
	http_server proxy;

	git_http_client *http_client;
} http_subtransport;

static int apply_url_credentials(
	git_cred **cred,
	unsigned int allowed_types,
	const char *username,
	const char *password)
{
	if (allowed_types & GIT_CREDTYPE_USERPASS_PLAINTEXT)
		return git_cred_userpass_plaintext_new(cred, username, password);

	if ((allowed_types & GIT_CREDTYPE_DEFAULT) && *username == '\0' && *password == '\0')
		return git_cred_default_new(cred);

	return GIT_PASSTHROUGH;
}

GIT_INLINE(void) free_cred(git_cred **cred)
{
	if (*cred) {
		git_cred_free(*cred);
		(*cred) = NULL;
	}
}

static int handle_auth(
	http_server *server,
	const char *server_type,
	const char *url,
	unsigned int allowed_schemetypes,
	unsigned int allowed_credtypes,
	git_cred_acquire_cb callback,
	void *callback_payload)
{
	int error = 1;

	if (server->cred)
		free_cred(&server->cred);

	/* Start with URL-specified credentials, if there were any. */
	if (!server->url_cred_presented &&
	    server->url.username &&
	    server->url.password) {
		error = apply_url_credentials(&server->cred, allowed_credtypes, server->url.username, server->url.password);
		server->url_cred_presented = 1;

		/* treat GIT_PASSTHROUGH as if callback isn't set */
		if (error == GIT_PASSTHROUGH)
			error = 1;
	}

	if (error > 0 && callback) {
		error = callback(&server->cred, url, server->url.username, allowed_credtypes, callback_payload);

		/* treat GIT_PASSTHROUGH as if callback isn't set */
		if (error == GIT_PASSTHROUGH)
			error = 1;
	}

	if (error > 0) {
		git_error_set(GIT_ERROR_NET, "%s authentication required but no callback set", server_type);
		error = -1;
	}

	if (!error)
		server->auth_schemetypes = allowed_schemetypes;

	return error;
}

GIT_INLINE(int) handle_remote_auth(
	http_stream *stream,
	git_http_response *response)
{
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);

	if (response->server_auth_credtypes == 0) {
		git_error_set(GIT_ERROR_NET, "server requires authentication that we do not support");
		return -1;
	}

	/* Otherwise, prompt for credentials. */
	return handle_auth(
		&transport->server,
		SERVER_TYPE_REMOTE,
		transport->owner->url,
		response->server_auth_schemetypes,
		response->server_auth_credtypes,
		transport->owner->cred_acquire_cb,
		transport->owner->cred_acquire_payload);
}

GIT_INLINE(int) handle_proxy_auth(
	http_stream *stream,
	git_http_response *response)
{
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);

	if (response->proxy_auth_credtypes == 0) {
		git_error_set(GIT_ERROR_NET, "proxy requires authentication that we do not support");
		return -1;
	}

	/* Otherwise, prompt for credentials. */
	return handle_auth(
		&transport->proxy,
		SERVER_TYPE_PROXY,
		transport->owner->proxy.url,
		response->server_auth_schemetypes,
		response->proxy_auth_credtypes,
		transport->owner->proxy.credentials,
		transport->owner->proxy.payload);
}


static int handle_response(
	bool *complete,
	http_stream *stream,
	git_http_response *response,
	bool allow_replay)
{
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);
	int error;

	*complete = false;

	if (allow_replay && git_http_response_is_redirect(response)) {
		if (!response->location) {
			git_error_set(GIT_ERROR_NET, "redirect without location");
			return -1;
		}

		if (git_net_url_apply_redirect(&transport->server.url, response->location, stream->service->url) < 0) {
			return -1;
		}

		return 0;
	} else if (git_http_response_is_redirect(response)) {
		git_error_set(GIT_ERROR_NET, "unexpected redirect");
		return -1;
	}

	/* If we're in the middle of challenge/response auth, continue. */
	if (allow_replay && response->resend_credentials) {
		return 0;
	} else if (allow_replay && response->status == 401) {
		if ((error = handle_remote_auth(stream, response)) < 0)
			return error;

		return git_http_client_skip_body(transport->http_client);
	} else if (allow_replay && response->status == 407) {
		if ((error = handle_proxy_auth(stream, response)) < 0)
			return error;

		return git_http_client_skip_body(transport->http_client);
	} else if (response->status == 401 || response->status == 407) {
		git_error_set(GIT_ERROR_NET, "unexpected authentication failure");
		return -1;
	}

	if (response->status != 200) {
		git_error_set(GIT_ERROR_NET, "unexpected http status code: %d", response->status);
		return -1;
	}

	/* The response must contain a Content-Type header. */
	if (!response->content_type) {
		git_error_set(GIT_ERROR_NET, "no content-type header in response");
		return -1;
	}

	/* The Content-Type header must match our expectation. */
	if (strcmp(response->content_type, stream->service->response_type) != 0) {
		git_error_set(GIT_ERROR_NET, "invalid content-type: '%s'", response->content_type);
		return -1;
	}

	*complete = true;
	stream->state = HTTP_STATE_RECEIVING_RESPONSE;
	return 0;
}

static int lookup_proxy(
	bool *out_use,
	http_subtransport *transport)
{
	const char *proxy;
	git_remote *remote;
	bool use_ssl;
	char *config = NULL;
	int error = 0;

	*out_use = false;
	git_net_url_dispose(&transport->proxy.url);

	switch (transport->owner->proxy.type) {
	case GIT_PROXY_SPECIFIED:
		proxy = transport->owner->proxy.url;
		break;

	case GIT_PROXY_AUTO:
		remote = transport->owner->owner;
		use_ssl = !strcmp(transport->server.url.scheme, "https");

		error = git_remote__get_http_proxy(remote, use_ssl, &config);

		if (error || !config)
			goto done;

		proxy = config;
		break;

	default:
		return 0;
	}

	if (!proxy ||
	    (error = git_net_url_parse(&transport->proxy.url, proxy)) < 0)
		goto done;

	*out_use = true;

done:
	git__free(config);
	return error;
}

static int generate_request(
	git_net_url *url,
	git_http_request *request,
	http_stream *stream,
	size_t len)
{
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);
	bool use_proxy = false;
	int error;

	if ((error = git_net_url_joinpath(url,
		&transport->server.url, stream->service->url)) < 0 ||
	    (error = lookup_proxy(&use_proxy, transport)) < 0)
		return error;

	request->method = stream->service->method;
	request->url = url;
	request->credentials = transport->server.cred;
	request->proxy = use_proxy ? &transport->proxy.url : NULL;
	request->proxy_credentials = transport->proxy.cred;

	if (stream->service->method == GIT_HTTP_METHOD_POST) {
		request->chunked = stream->service->chunked;
		request->content_length = stream->service->chunked ? 0 : len;
		request->content_type = stream->service->request_type;
		request->accept = stream->service->response_type;
		request->expect_continue = git_http__expect_continue;
	}

	return 0;
}

/*
 * Read from an HTTP transport - for the first invocation of this function
 * (ie, when stream->state == HTTP_STATE_NONE), we'll send a GET request
 * to the remote host.  We will stream that data back on all subsequent
 * calls.
 */
static int http_stream_read(
	git_smart_subtransport_stream *s,
	char *buffer,
	size_t buffer_size,
	size_t *out_len)
{
	http_stream *stream = (http_stream *)s;
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);
	git_net_url url = GIT_NET_URL_INIT;
	git_net_url proxy_url = GIT_NET_URL_INIT;
	git_http_request request = {0};
	git_http_response response = {0};
	bool complete;
	int error;

	*out_len = 0;

	if (stream->state == HTTP_STATE_NONE) {
		stream->state = HTTP_STATE_SENDING_REQUEST;
		stream->replay_count = 0;
	}

	/*
	 * Formulate the URL, send the request and read the response
	 * headers.  Some of the request body may also be read.
	 */
	while (stream->state == HTTP_STATE_SENDING_REQUEST &&
	       stream->replay_count < GIT_HTTP_REPLAY_MAX) {
		git_net_url_dispose(&url);
		git_net_url_dispose(&proxy_url);
		git_http_response_dispose(&response);

		if ((error = generate_request(&url, &request, stream, 0)) < 0 ||
		    (error = git_http_client_send_request(
			transport->http_client, &request)) < 0 ||
		    (error = git_http_client_read_response(
			    &response, transport->http_client)) < 0 ||
		    (error = handle_response(&complete, stream, &response, true)) < 0)
			goto done;

		if (complete)
			break;

		stream->replay_count++;
	}

	if (stream->state == HTTP_STATE_SENDING_REQUEST) {
		git_error_set(GIT_ERROR_NET, "too many redirects or authentication replays");
		error = -1;
		goto done;
	}

	assert (stream->state == HTTP_STATE_RECEIVING_RESPONSE);

	error = git_http_client_read_body(transport->http_client, buffer, buffer_size);

	if (error > 0) {
		*out_len = error;
		error = 0;
	}

done:
	git_net_url_dispose(&url);
	git_net_url_dispose(&proxy_url);
	git_http_response_dispose(&response);

	return error;
}

static bool needs_probe(http_stream *stream)
{
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);

	return (transport->server.auth_schemetypes == GIT_AUTHTYPE_NTLM ||
	        transport->server.auth_schemetypes == GIT_AUTHTYPE_NEGOTIATE);
}

static int send_probe(http_stream *stream)
{
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);
	git_http_client *client = transport->http_client;
	const char *probe = "0000";
	size_t len = 4;
	git_net_url url = GIT_NET_URL_INIT;
	git_http_request request = {0};
	git_http_response response = {0};
	bool complete = false;
	size_t step, steps;
	int error;

	/* NTLM takes two round-trips; Negotiate takes one. */
	if (transport->server.auth_schemetypes == GIT_AUTHTYPE_NTLM) {
		steps = 2;
	} else if (transport->server.auth_schemetypes == GIT_AUTHTYPE_NEGOTIATE) {
		steps = 1;
	} else {
		git_error_set(GIT_ERROR_NET, "unknown authentication scheme");
		error = -1;
		goto done;
	}

	/*
	 * Send at most two requests: one without any authentication to see
	 * if we get prompted to authenticate.  If we do, send a second one
	 * with the first authentication message.  The final authentication
	 * message with the response will occur with the *actual* POST data.
	 */
	for (step = 0; step < steps && !complete; step++) {
		if ((error = generate_request(&url, &request, stream, len)) < 0 ||
		    (error = git_http_client_send_request(client, &request)) < 0 ||
		    (error = git_http_client_send_body(client, probe, len)) < 0 ||
		    (error = git_http_client_read_response(&response, client)) < 0 ||
		    (error = git_http_client_skip_body(client)) < 0 ||
		    (error = handle_response(&complete, stream, &response, true)) < 0)
			goto done;
	}

done:
	git_http_response_dispose(&response);
	git_net_url_dispose(&url);
	return error;
}

/*
* Write to an HTTP transport - for the first invocation of this function
* (ie, when stream->state == HTTP_STATE_NONE), we'll send a POST request
* to the remote host.  If we're sending chunked data, then subsequent calls
* will write the additional data given in the buffer.  If we're not chunking,
* then the caller should have given us all the data in the original call.
* The caller should call http_stream_read_response to get the result.
*/
static int http_stream_write(
	git_smart_subtransport_stream *s,
	const char *buffer,
	size_t len)
{
	http_stream *stream = GIT_CONTAINER_OF(s, http_stream, parent);
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);
	git_net_url url = GIT_NET_URL_INIT;
	git_http_request request = {0};
	git_http_response response = {0};
	int error;

	while (stream->state == HTTP_STATE_NONE &&
	       stream->replay_count < GIT_HTTP_REPLAY_MAX) {

		/*
		 * If we're authenticating with a multi-step mechanism
		 * (NTLM, Kerberos), send a "probe" packet.  Servers SHOULD
		 * authenticate an entire keep-alive connection, so ideally
		 * we should not need to authenticate but some servers do
		 * not support this.  By sending a probe packet, we'll be
		 * able to follow up with a second POST using the actual
		 * data (and, in the degenerate case, the authentication
		 * header as well).
		 */
		if (needs_probe(stream) && (error = send_probe(stream)) < 0)
			goto done;

		/* Send the regular POST request. */
		if ((error = generate_request(&url, &request, stream, len)) < 0 ||
		    (error = git_http_client_send_request(
			transport->http_client, &request)) < 0)
			goto done;

		if (request.expect_continue &&
		    git_http_client_has_response(transport->http_client)) {
			bool complete;

			/*
			 * If we got a response to an expect/continue, then
			 * it's something other than a 100 and we should
			 * deal with the response somehow.
			 */
			if ((error = git_http_client_read_response(&response, transport->http_client)) < 0 ||
			   (error = handle_response(&complete, stream, &response, true)) < 0)
			    goto done;
		} else {
			stream->state = HTTP_STATE_SENDING_REQUEST;
		}

		stream->replay_count++;
	}

	if (stream->state == HTTP_STATE_NONE) {
		git_error_set(GIT_ERROR_NET,
		              "too many redirects or authentication replays");
		error = -1;
		goto done;
	}

	assert(stream->state == HTTP_STATE_SENDING_REQUEST);

	error = git_http_client_send_body(transport->http_client, buffer, len);

done:
	git_http_response_dispose(&response);
	git_net_url_dispose(&url);
	return error;
}

/*
* Read from an HTTP transport after it has been written to.  This is the
* response from a POST request made by http_stream_write.
*/
static int http_stream_read_response(
	git_smart_subtransport_stream *s,
	char *buffer,
	size_t buffer_size,
	size_t *out_len)
{
	http_stream *stream = (http_stream *)s;
	http_subtransport *transport = OWNING_SUBTRANSPORT(stream);
	git_http_client *client = transport->http_client;
	git_http_response response = {0};
	bool complete;
	int error;

	*out_len = 0;

	if (stream->state == HTTP_STATE_SENDING_REQUEST) {
		if ((error = git_http_client_read_response(&response, client)) < 0 ||
		    (error = handle_response(&complete, stream, &response, false)) < 0)
		    goto done;

		assert(complete);
		stream->state = HTTP_STATE_RECEIVING_RESPONSE;
	}

	error = git_http_client_read_body(client, buffer, buffer_size);

	if (error > 0) {
		*out_len = error;
		error = 0;
	}

done:
	git_http_response_dispose(&response);
	return error;
}

static void http_stream_free(git_smart_subtransport_stream *stream)
{
	http_stream *s = GIT_CONTAINER_OF(stream, http_stream, parent);
	git__free(s);
}

static git_http_service *select_service(git_smart_service_t action)
{
	switch (action) {
	case GIT_SERVICE_UPLOADPACK_LS:
		return &upload_pack_ls_service;
	case GIT_SERVICE_UPLOADPACK:
		return &upload_pack_service;
	case GIT_SERVICE_RECEIVEPACK_LS:
		return &receive_pack_ls_service;
	case GIT_SERVICE_RECEIVEPACK:
		return &receive_pack_service;
	}

	return NULL;
}

static int http_action(
	git_smart_subtransport_stream **out,
	git_smart_subtransport *t,
	const char *url,
	git_smart_service_t action)
{
	http_subtransport *transport = GIT_CONTAINER_OF(t, http_subtransport, parent);
	http_stream *stream;
	git_http_service *service;
	int error;

	assert(out && t);

	*out = NULL;

	/*
	 * If we've seen a redirect then preserve the location that we've
	 * been given.  This is important to continue authorization against
	 * the redirect target, not the user-given source; the endpoint may
	 * have redirected us from HTTP->HTTPS and is using an auth mechanism
	 * that would be insecure in plaintext (eg, HTTP Basic).
	 */
	if (!git_net_url_valid(&transport->server.url) &&
	    (error = git_net_url_parse(&transport->server.url, url)) < 0)
		return error;

	if ((service = select_service(action)) == NULL) {
		git_error_set(GIT_ERROR_NET, "invalid action");
		return -1;
	}

	stream = git__calloc(sizeof(http_stream), 1);
	GIT_ERROR_CHECK_ALLOC(stream);

	if (!transport->http_client) {
		git_http_client_options opts = {0};

		opts.server_certificate_check_cb = transport->owner->certificate_check_cb;
		opts.server_certificate_check_payload = transport->owner->message_cb_payload;
		opts.proxy_certificate_check_cb = transport->owner->proxy.certificate_check;
		opts.proxy_certificate_check_payload = transport->owner->proxy.payload;

		if (git_http_client_new(&transport->http_client, &opts) < 0)
			return -1;
	}

	stream->service = service;
	stream->parent.subtransport = &transport->parent;

	if (service->method == GIT_HTTP_METHOD_GET) {
		stream->parent.read = http_stream_read;
	} else {
		stream->parent.write = http_stream_write;
		stream->parent.read = http_stream_read_response;
	}

	stream->parent.free = http_stream_free;

	*out = (git_smart_subtransport_stream *)stream;
	return 0;
}

static int http_close(git_smart_subtransport *t)
{
	http_subtransport *transport = GIT_CONTAINER_OF(t, http_subtransport, parent);

	free_cred(&transport->server.cred);
	free_cred(&transport->proxy.cred);

	transport->server.url_cred_presented = false;
	transport->proxy.url_cred_presented = false;

	git_net_url_dispose(&transport->server.url);
	git_net_url_dispose(&transport->proxy.url);

	return 0;
}

static void http_free(git_smart_subtransport *t)
{
	http_subtransport *transport = GIT_CONTAINER_OF(t, http_subtransport, parent);

	git_http_client_free(transport->http_client);

	http_close(t);
	git__free(transport);
}

int git_smart_subtransport_http(git_smart_subtransport **out, git_transport *owner, void *param)
{
	http_subtransport *transport;

	GIT_UNUSED(param);

	assert(out);

	transport = git__calloc(sizeof(http_subtransport), 1);
	GIT_ERROR_CHECK_ALLOC(transport);

	transport->owner = (transport_smart *)owner;
	transport->parent.action = http_action;
	transport->parent.close = http_close;
	transport->parent.free = http_free;

	*out = (git_smart_subtransport *) transport;
	return 0;
}

#endif /* !GIT_WINHTTP */
