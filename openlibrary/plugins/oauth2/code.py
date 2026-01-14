"""
OpenLibrary OAuth2 Plugin

This plugin provides OAuth2 authentication endpoints for OpenLibrary.
"""

import json
import logging

import web

from infogami.utils import delegate
from openlibrary.oauth2.provider import oauth2_handler

logger = logging.getLogger("openlibrary.oauth2")


class oauth2_test(delegate.page):
    """Simple test endpoint to verify plugin is working"""

    path = "/oauth2/test"

    def GET(self):
        return "OAuth2 Plugin Test - Working!"


class oauth2_authorize(delegate.page):
    """OAuth2 Authorization Endpoint"""

    path = "/oauth2/authorize"

    def GET(self):
        try:
            # Check if this is a simple test request (no parameters)
            i = web.input(response_type=None, client_id=None, redirect_uri=None)
            if not any([i.response_type, i.client_id, i.redirect_uri]):
                # Simple test response for debugging
                web.header("Content-Type", "text/html")
                return """
                <html>
                <head><title>OAuth2 Test</title></head>
                <body>
                    <h1>OAuth2 Authorize Endpoint</h1>
                    <p>Provide parameters to test the full OAuth2 flow.</p>
                    <p><strong>Required parameters:</strong> response_type, client_id, redirect_uri</p>
                </body>
                </html>
                """

            return oauth2_handler.authorize()
        except web.HTTPError:
            # Let web.py handle redirects and HTTP errors
            raise
        except Exception as e:
            logger.error(f"OAuth2 authorize error: {e!s}", exc_info=True)
            web.ctx.status = "500 Internal Server Error"
            return f"OAuth2 Error: {e!s}"


class oauth2_authorize_complete(delegate.page):
    """OAuth2 Authorization Complete Endpoint"""

    path = "/oauth2/authorize/complete"

    def GET(self):
        try:
            return oauth2_handler.authorize_complete()
        except web.HTTPError:
            raise


class oauth2_token(delegate.page):
    """OAuth2 Token Endpoint"""

    path = "/oauth2/token"

    def POST(self):
        try:
            return oauth2_handler.token()
        except web.HTTPError:
            raise


class oauth2_userinfo(delegate.page):
    """OAuth2 User Info Endpoint"""

    path = "/oauth2/userinfo"

    def GET(self):
        try:
            return oauth2_handler.userinfo()
        except web.HTTPError:
            raise


class oauth2_token_to_cookie(delegate.page):
    """Exchange OAuth2 Token for Session Cookie"""

    path = "/oauth2/token-to-cookie"

    def POST(self):
        try:
            return oauth2_handler.token_to_cookie()
        except web.HTTPError:
            raise
        except Exception as e:
            logger.error(f"Exception in token_to_cookie endpoint: {e!s}", exc_info=True)
            web.ctx.status = "500"
            error_response = {"error": "server_error", "error_description": str(e)}
            return delegate.RawText(
                json.dumps(error_response), content_type="application/json"
            )


def setup():
    """Set up OAuth2 plugin."""
    # Register default OAuth2 clients
    # In production, this would be loaded from configuration
    oauth2_handler.setup_default_clients()
