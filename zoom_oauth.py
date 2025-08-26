#!/usr/bin/env python3

"""
Zoom OAuth Authentication Module
Supports both Server-to-Server and User-Managed OAuth flows
"""

import base64
import webbrowser
import requests
import requests.auth
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode

class Color:
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    DARK_CYAN = "\033[36m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback"""

    def do_GET(self):
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)

        # Check for errors first
        if 'error' in params:
            error = params['error'][0]
            error_desc = params.get('error_description', [''])[0]
            self.send_error_response(f"OAuth Error: {error} - {error_desc}")
            self.server.auth_code = None
            self.server.error_message = f"{error}: {error_desc}"
            return

        if 'code' in params:
            self.server.auth_code = params['code'][0]
            self.send_success_response()
        else:
            self.send_error_response("No authorization code received")
            self.server.auth_code = None
            self.server.error_message = "No authorization code in callback"

    def send_success_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        success_html = '''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Zoom OAuth Success</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                    .success { color: #28a745; }
                </style>
            </head>
            <body>
                <h1 class="success">✅ Authorization Successful!</h1>
                <p>You have successfully authorized the Zoom Recording Downloader.</p>
                <p><strong>You can close this window and return to the application.</strong></p>
            </body>
            </html>
        '''
        self.wfile.write(success_html.encode('utf-8'))

    def send_error_response(self, message):
        self.send_response(400)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        error_html = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Zoom OAuth Error</title>
                <style>
                    body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                    .error {{ color: #dc3545; }}
                </style>
            </head>
            <body>
                <h1 class="error">❌ Authorization Failed</h1>
                <p>{message}</p>
                <p>Please close this window and try again.</p>
            </body>
            </html>
        '''
        self.wfile.write(error_html.encode('utf-8'))

    def log_message(self, format, *args):
        # Suppress default HTTP server logging
        pass

class ZoomOAuth:
    """Zoom OAuth Authentication Handler"""

    def __init__(self, config):
        self.config = config
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.account_id = config.get("account_id")  # Only for server-to-server
        self.oauth_method = config.get("oauth_method", "server_to_server")
        self.redirect_uri = config.get("redirect_uri", "http://localhost:8080/oauth/callback")
        self.scopes = config.get("scopes", "recording:read user:read")

        self.access_token = None
        self.authorization_header = None

    def authenticate(self):
        """Main authentication method - chooses flow based on config"""
        if self.oauth_method.lower() == "user_managed":
            return self._user_managed_oauth()
        else:
            return self._server_to_server_oauth()

    def _server_to_server_oauth(self):
        """Server-to-Server OAuth flow (original implementation)"""
        print(f"{Color.DARK_CYAN}Using Server-to-Server OAuth authentication...{Color.END}")

        if not all([self.client_id, self.client_secret, self.account_id]):
            print(f"{Color.RED}### Missing required credentials for Server-to-Server OAuth{Color.END}")
            return False

        url = f"https://zoom.us/oauth/token?grant_type=account_credentials&account_id={self.account_id}"

        client_cred = f"{self.client_id}:{self.client_secret}"
        client_cred_base64_string = base64.b64encode(client_cred.encode("utf-8")).decode("utf-8")

        headers = {
            "Authorization": f"Basic {client_cred_base64_string}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            response = requests.post(url, headers=headers, timeout=30)
            response.raise_for_status()
            token_data = response.json()

            self.access_token = token_data["access_token"]
            self.authorization_header = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }

            print(f"{Color.GREEN}✅ Server-to-Server OAuth authentication successful!{Color.END}")
            return True

        except requests.RequestException as e:
            print(f"{Color.RED}### Server-to-Server OAuth failed: {e}{Color.END}")
            return False
        except KeyError:
            print(f"{Color.RED}### The key 'access_token' wasn't found in response{Color.END}")
            return False

    def _user_managed_oauth(self):
        """User-Managed OAuth flow (new implementation)"""
        print(f"{Color.DARK_CYAN}Using User-Managed OAuth authentication...{Color.END}")

        if not all([self.client_id, self.client_secret]):
            print(f"{Color.RED}### Missing required credentials for User-Managed OAuth{Color.END}")
            return False

        access_token = self._start_oauth_flow()
        if access_token:
            self.access_token = access_token
            self.authorization_header = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            print(f"{Color.GREEN}✅ User-Managed OAuth authentication successful!{Color.END}")
            return True
        else:
            print(f"{Color.RED}### User-Managed OAuth authentication failed!{Color.END}")
            return False

    def _make_authorization_url(self):
        """Generate Zoom OAuth authorization URL"""
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri
            # Note: Zoom doesn't support scope parameter in authorization URL
            # Scopes are determined by what's configured in the Zoom app settings
        }
        return "https://zoom.us/oauth/authorize?" + urlencode(params)

    def _get_token(self, code):
        """Exchange authorization code for access token"""
        client_auth = requests.auth.HTTPBasicAuth(self.client_id, self.client_secret)
        post_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri
        }

        try:
            response = requests.post("https://zoom.us/oauth/token",
                                   auth=client_auth,
                                   data=post_data,
                                   timeout=30)
            response.raise_for_status()
            token_json = response.json()
            return token_json["access_token"]
        except requests.RequestException as e:
            print(f"{Color.RED}Token exchange failed: {e}{Color.END}")
            return None
        except KeyError as e:
            print(f"{Color.RED}Missing key in token response: {e}{Color.END}")
            return None

    def _start_oauth_flow(self):
        """Start OAuth flow with local callback server"""
        try:
            # Start server
            server = HTTPServer(('localhost', 8080), OAuthCallbackHandler)
            server.timeout = 120  # 2 minute timeout

            # Generate and open authorization URL
            auth_url = self._make_authorization_url()
            print(f"{Color.CYAN}Opening browser for Zoom authorization...{Color.END}")
            print(f"{Color.YELLOW}If browser doesn't open automatically, visit:{Color.END}")
            print(f"{Color.UNDERLINE}{auth_url}{Color.END}")

            webbrowser.open(auth_url)

            # Wait for callback
            print(f"{Color.CYAN}Waiting for authorization (timeout: 2 minutes)...{Color.END}")
            print(f"{Color.YELLOW}Please complete the authorization in your browser{Color.END}")

            server.handle_request()

            auth_code = getattr(server, 'auth_code', None)
            error_message = getattr(server, 'error_message', None)

            if auth_code:
                print(f"{Color.CYAN}Authorization code received, exchanging for token...{Color.END}")
                access_token = self._get_token(auth_code)
                return access_token
            else:
                if error_message:
                    print(f"{Color.RED}Authorization failed: {error_message}{Color.END}")
                else:
                    print(f"{Color.RED}Authorization failed or timed out{Color.END}")
                return None

        except OSError as e:
            if "Address already in use" in str(e):
                print(f"{Color.RED}### Port 8080 is already in use. Please close other applications using this port.{Color.END}")
            else:
                print(f"{Color.RED}### Failed to start OAuth server: {e}{Color.END}")
            return None
        except Exception as e:
            print(f"{Color.RED}### OAuth flow failed: {e}{Color.END}")
            return None

    def get_authorization_header(self):
        """Get the authorization header for API requests"""
        return self.authorization_header

    def get_access_token(self):
        """Get the access token"""
        return self.access_token

    def test_authentication(self):
        """Test the authentication by making a simple API call"""
        if not self.authorization_header:
            return False

        try:
            response = requests.get("https://api.zoom.us/v2/users/me",
                                  headers=self.authorization_header,
                                  timeout=10)
            if response.status_code == 200:
                user_info = response.json()
                print(f"{Color.GREEN}✅ Authentication test successful!{Color.END}")
                print(f"{Color.CYAN}Authenticated as: {user_info.get('email', 'Unknown')} ({user_info.get('first_name', '')} {user_info.get('last_name', '')}){Color.END}")
                return True
            else:
                print(f"{Color.RED}### Authentication test failed: HTTP {response.status_code}{Color.END}")
                return False
        except requests.RequestException as e:
            print(f"{Color.RED}### Authentication test failed: {e}{Color.END}")
            return False
