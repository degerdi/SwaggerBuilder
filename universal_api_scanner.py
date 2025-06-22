#!/usr/bin/env python3


"""
Universal API Parameter Scanner - Enhanced with Swagger Documentation Output
Comprehensive tool for discovering, analyzing, and documenting REST APIs
"""
import requests
import json
import re
import time
import argparse
import csv
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs
from collections import defaultdict, Counter
from datetime import datetime

import yaml
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
import concurrent.futures
from dataclasses import dataclass, asdict
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """Data class for storing endpoint information"""
    path: str
    method: str
    parameters: Dict[str, Any]
    headers: Dict[str, str]
    status_code: int
    response_time: float
    response_body: str
    response_headers: Dict[str, str]
    content_type: str
    error: Optional[str] = None
    schema: Optional[Dict] = None
    examples: List[Dict] = None


@dataclass
class APIAnalysis:
    """Data class for storing complete API analysis"""
    base_url: str
    discovered_endpoints: List[APIEndpoint]
    parameter_patterns: Dict[str, List[str]]
    authentication_methods: List[str]
    error_patterns: Dict[int, List[str]]
    rate_limits: Dict[str, Any]
    security_findings: List[str]
    performance_stats: Dict[str, float]


class UniversalAPIScanner:
    """Universal API Scanner for any REST API"""

    def __init__(self, base_url: str, **kwargs):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.endpoints = []
        self.discovered_paths = set()
        self.parameter_patterns = defaultdict(list)
        self.error_patterns = defaultdict(list)
        self.rate_limits = {}
        self.security_findings = []
        self.performance_stats = {}

        # Configuration options
        self.timeout = kwargs.get('timeout', 30)
        self.max_workers = kwargs.get('max_workers', 10)
        self.rate_limit_delay = kwargs.get('rate_limit_delay', 0.1)
        self.auth_headers = kwargs.get('auth_headers', {})
        self.custom_headers = kwargs.get('custom_headers', {})
        self.follow_redirects = kwargs.get('follow_redirects', True)
        self.verify_ssl = kwargs.get('verify_ssl', True)
        self.deep_scan = kwargs.get('deep_scan', False)

        # Enhanced authentication options
        self.credentials = kwargs.get('credentials', {})
        self.auth_method = kwargs.get('auth_method', 'auto')
        self.login_endpoint = kwargs.get('login_endpoint', None)
        self.token_endpoint = kwargs.get('token_endpoint', None)
        self.refresh_endpoint = kwargs.get('refresh_endpoint', None)
        self.logout_endpoint = kwargs.get('logout_endpoint', None)

        # Session management
        self.authenticated = False
        self.auth_token = None
        self.refresh_token = None
        self.session_cookies = {}
        self.csrf_token = None

        # Setup session
        self._setup_session()

        # Thread lock for thread-safe operations
        self.lock = threading.Lock()

    def _setup_session(self):
        """Configure the requests session with authentication"""
        self.session.timeout = self.timeout
        self.session.verify = self.verify_ssl

        # Default headers
        default_headers = {
            'User-Agent': 'Universal-API-Scanner/1.0',
            'Accept': 'application/json, application/xml, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache'
        }

        # Merge with custom headers
        headers = {**default_headers, **self.custom_headers, **self.auth_headers}
        self.session.headers.update(headers)

        # Attempt authentication if credentials provided
        if self.credentials:
            self._authenticate()

        logger.info(f"Session configured for {self.base_url}")

    def _authenticate(self):
        """Perform authentication based on provided credentials and method"""
        try:
            if self.auth_method == 'auto':
                self._auto_detect_auth_method()
            elif self.auth_method == 'basic':
                self._setup_basic_auth()
            elif self.auth_method == 'bearer':
                self._setup_bearer_auth()
            elif self.auth_method == 'api_key':
                self._setup_api_key_auth()
            elif self.auth_method == 'oauth2':
                self._perform_oauth2_auth()
            elif self.auth_method == 'jwt':
                self._perform_jwt_auth()
            elif self.auth_method == 'session':
                self._perform_session_auth()
            elif self.auth_method == 'custom':
                self._perform_custom_auth()

        except Exception as e:
            logger.warning(f"Authentication failed: {e}")

    def _auto_detect_auth_method(self):
        """Automatically detect the authentication method"""
        logger.info("Auto-detecting authentication method...")

        # Check if token is already provided in credentials
        if 'token' in self.credentials:
            if self.credentials['token'].startswith('Bearer '):
                self._setup_bearer_auth()
            elif 'jwt' in self.credentials.get('token_type', '').lower():
                self._setup_bearer_auth()  # JWT typically uses Bearer
            else:
                self._setup_bearer_auth()  # Default to Bearer
            return

        # Check if API key is provided
        if 'api_key' in self.credentials:
            self._setup_api_key_auth()
            return

        # Check if username/password provided
        if 'username' in self.credentials and 'password' in self.credentials:
            # Try to detect auth method by testing endpoints
            auth_methods_to_try = ['session', 'jwt', 'oauth2', 'basic']

            for method in auth_methods_to_try:
                try:
                    original_method = self.auth_method
                    self.auth_method = method

                    if method == 'session':
                        self._perform_session_auth()
                    elif method == 'jwt':
                        self._perform_jwt_auth()
                    elif method == 'oauth2':
                        self._perform_oauth2_auth()
                    elif method == 'basic':
                        self._setup_basic_auth()

                    # Test if authentication worked
                    if self._test_authentication():
                        logger.info(f"Successfully authenticated using {method}")
                        return

                    self.auth_method = original_method

                except Exception as e:
                    logger.debug(f"Auth method {method} failed: {e}")
                    continue

            logger.warning("Could not auto-detect authentication method")

    def _setup_basic_auth(self):
        """Setup Basic Authentication"""
        username = self.credentials.get('username')
        password = self.credentials.get('password')

        if username and password:
            import base64
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.session.headers['Authorization'] = f"Basic {credentials}"
            self.authenticated = True
            logger.info("Basic authentication configured")

    def _setup_bearer_auth(self):
        """Setup Bearer Token Authentication"""
        token = self.credentials.get('token')

        if token:
            if not token.startswith('Bearer '):
                token = f"Bearer {token}"
            self.session.headers['Authorization'] = token
            self.auth_token = token
            self.authenticated = True
            logger.info("Bearer authentication configured")

    def _setup_api_key_auth(self):
        """Setup API Key Authentication"""
        api_key = self.credentials.get('api_key')
        key_header = self.credentials.get('api_key_header', 'X-API-Key')

        if api_key:
            self.session.headers[key_header] = api_key
            self.authenticated = True
            logger.info(f"API Key authentication configured ({key_header})")

    def _perform_session_auth(self):
        """Perform session-based authentication (login with username/password)"""
        username = self.credentials.get('username')
        password = self.credentials.get('password')

        if not (username and password):
            raise ValueError("Username and password required for session authentication")

        # Try to find login endpoint
        login_url = self._find_login_endpoint()

        if not login_url:
            raise ValueError("Could not find login endpoint")

        # Prepare login payload
        login_data = {
            'username': username,
            'password': password
        }

        # Try common field names
        field_variations = [
            {'username': username, 'password': password},
            {'email': username, 'password': password},
            {'user': username, 'pass': password},
            {'login': username, 'password': password},
            {'user_name': username, 'user_password': password}
        ]

        for login_payload in field_variations:
            try:
                # Get CSRF token if needed
                self._get_csrf_token(login_url)

                if self.csrf_token:
                    login_payload['csrf_token'] = self.csrf_token

                response = self.session.post(login_url, json=login_payload, timeout=15)

                if response.status_code in [200, 201, 302]:
                    # Check for success indicators
                    if self._validate_login_response(response):
                        self.authenticated = True
                        self.session_cookies = dict(self.session.cookies)
                        logger.info("Session authentication successful")
                        return

            except Exception as e:
                logger.debug(f"Login attempt failed with payload {login_payload}: {e}")
                continue

        raise ValueError("Session authentication failed with all login variations")

    def _perform_jwt_auth(self):
        """Perform JWT authentication"""
        username = self.credentials.get('username')
        password = self.credentials.get('password')

        if not (username and password):
            raise ValueError("Username and password required for JWT authentication")

        # Try to find token endpoint
        token_url = self._find_token_endpoint()

        if not token_url:
            raise ValueError("Could not find JWT token endpoint")

        # Prepare token request
        token_data = {
            'username': username,
            'password': password
        }

        # Try different JWT request formats
        jwt_variations = [
            {'username': username, 'password': password},
            {'email': username, 'password': password},
            {'grant_type': 'password', 'username': username, 'password': password},
            {'grant_type': 'client_credentials', 'client_id': username, 'client_secret': password}
        ]

        for jwt_payload in jwt_variations:
            try:
                response = self.session.post(token_url, json=jwt_payload, timeout=15)

                if response.status_code in [200, 201]:
                    token_data = response.json()

                    # Extract token from response
                    token = (token_data.get('access_token') or
                             token_data.get('token') or
                             token_data.get('jwt') or
                             token_data.get('authToken'))

                    if token:
                        self.auth_token = f"Bearer {token}"
                        self.session.headers['Authorization'] = self.auth_token

                        # Store refresh token if available
                        self.refresh_token = token_data.get('refresh_token')

                        self.authenticated = True
                        logger.info("JWT authentication successful")
                        return

            except Exception as e:
                logger.debug(f"JWT auth failed with payload {jwt_payload}: {e}")
                continue

        raise ValueError("JWT authentication failed")

    def _perform_oauth2_auth(self):
        """Perform OAuth2 authentication"""
        client_id = self.credentials.get('client_id')
        client_secret = self.credentials.get('client_secret')
        username = self.credentials.get('username')
        password = self.credentials.get('password')

        if not (client_id and client_secret):
            raise ValueError("Client ID and secret required for OAuth2")

        # Find OAuth2 token endpoint
        token_url = self._find_oauth_endpoint()

        if not token_url:
            raise ValueError("Could not find OAuth2 token endpoint")

        # Try different OAuth2 flows
        oauth_flows = []

        # Client credentials flow
        oauth_flows.append({
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret
        })

        # Resource owner password flow (if username/password provided)
        if username and password:
            oauth_flows.append({
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password
            })

        for oauth_payload in oauth_flows:
            try:
                response = self.session.post(
                    token_url,
                    data=oauth_payload,  # OAuth2 typically uses form data
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=15
                )

                if response.status_code in [200, 201]:
                    token_data = response.json()
                    access_token = token_data.get('access_token')

                    if access_token:
                        self.auth_token = f"Bearer {access_token}"
                        self.session.headers['Authorization'] = self.auth_token
                        self.refresh_token = token_data.get('refresh_token')
                        self.authenticated = True
                        logger.info("OAuth2 authentication successful")
                        return

            except Exception as e:
                logger.debug(f"OAuth2 flow failed: {e}")
                continue

        raise ValueError("OAuth2 authentication failed")

    def _perform_custom_auth(self):
        """Perform custom authentication based on provided parameters"""
        custom_auth = self.credentials.get('custom_auth', {})

        if not custom_auth:
            raise ValueError("Custom auth configuration required")

        auth_url = custom_auth.get('url')
        auth_method = custom_auth.get('method', 'POST')
        auth_payload = custom_auth.get('payload', {})
        auth_headers = custom_auth.get('headers', {})

        if not auth_url:
            raise ValueError("Custom auth URL required")

        try:
            # Merge custom headers
            headers = {**self.session.headers, **auth_headers}

            response = self.session.request(
                method=auth_method,
                url=urljoin(self.base_url, auth_url),
                json=auth_payload if auth_method.upper() in ['POST', 'PUT', 'PATCH'] else None,
                params=auth_payload if auth_method.upper() == 'GET' else None,
                headers=headers,
                timeout=15
            )

            if response.status_code in [200, 201, 302]:
                # Extract token from response
                response_data = response.json() if response.headers.get('Content-Type', '').startswith(
                    'application/json') else {}

                token_field = custom_auth.get('token_field', 'token')
                token = response_data.get(token_field)

                if token:
                    auth_header = custom_auth.get('auth_header', 'Authorization')
                    token_prefix = custom_auth.get('token_prefix', 'Bearer')

                    self.session.headers[auth_header] = f"{token_prefix} {token}"
                    self.auth_token = token
                    self.authenticated = True
                    logger.info("Custom authentication successful")
                    return

        except Exception as e:
            logger.debug(f"Custom auth failed: {e}")

        raise ValueError("Custom authentication failed")

    def _find_login_endpoint(self) -> Optional[str]:
        """Find login endpoint through common patterns"""
        if self.login_endpoint:
            return urljoin(self.base_url, self.login_endpoint)

        login_patterns = [
            '/login', '/auth/login', '/api/login', '/api/auth/login',
            '/signin', '/auth/signin', '/api/signin', '/api/auth/signin',
            '/authenticate', '/auth/authenticate', '/api/authenticate',
            '/session', '/auth/session', '/api/session',
            '/v1/login', '/v1/auth/login', '/v2/login', '/v2/auth/login'
        ]

        for pattern in login_patterns:
            try:
                url = urljoin(self.base_url, pattern)
                response = self.session.get(url, timeout=5)

                # Check if this looks like a login endpoint
                if (response.status_code in [200, 405] or  # 405 = Method Not Allowed (POST expected)
                        'login' in response.text.lower() or
                        'username' in response.text.lower() or
                        'password' in response.text.lower()):
                    return url

            except Exception:
                continue

        return None

    def _find_token_endpoint(self) -> Optional[str]:
        """Find JWT/token endpoint"""
        if self.token_endpoint:
            return urljoin(self.base_url, self.token_endpoint)

        token_patterns = [
            '/token', '/auth/token', '/api/token', '/api/auth/token',
            '/jwt', '/auth/jwt', '/api/jwt', '/api/auth/jwt',
            '/oauth/token', '/oauth2/token', '/api/oauth/token',
            '/v1/token', '/v1/auth/token', '/v2/token', '/v2/auth/token'
        ]

        for pattern in token_patterns:
            try:
                url = urljoin(self.base_url, pattern)
                response = self.session.get(url, timeout=5)

                if response.status_code in [200, 405, 401]:  # These indicate a valid endpoint
                    return url

            except Exception:
                continue

        return None

    def _find_oauth_endpoint(self) -> Optional[str]:
        """Find OAuth2 token endpoint"""
        if self.token_endpoint:
            return urljoin(self.base_url, self.token_endpoint)

        # Try .well-known endpoint first
        try:
            well_known_url = urljoin(self.base_url, '/.well-known/oauth-authorization-server')
            response = self.session.get(well_known_url, timeout=5)

            if response.status_code == 200:
                config = response.json()
                token_endpoint = config.get('token_endpoint')
                if token_endpoint:
                    return token_endpoint

        except Exception:
            pass

        oauth_patterns = [
            '/oauth/token', '/oauth2/token', '/api/oauth/token', '/api/oauth2/token',
            '/auth/oauth/token', '/auth/oauth2/token', '/token',
            '/v1/oauth/token', '/v2/oauth/token'
        ]

        for pattern in oauth_patterns:
            try:
                url = urljoin(self.base_url, pattern)
                response = self.session.get(url, timeout=5)

                if response.status_code in [200, 405, 401]:
                    return url

            except Exception:
                continue

        return None

    def _get_csrf_token(self, url: str):
        """Get CSRF token for session authentication"""
        try:
            response = self.session.get(url, timeout=10)

            # Look for CSRF token in various places
            csrf_patterns = [
                r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'authenticity_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'<input[^>]*name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
                r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']'
            ]

            for pattern in csrf_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    self.csrf_token = match.group(1)
                    logger.debug(f"Found CSRF token: {self.csrf_token[:10]}...")
                    return

        except Exception as e:
            logger.debug(f"Could not get CSRF token: {e}")

    def _validate_login_response(self, response: requests.Response) -> bool:
        """Validate if login was successful"""
        # Check status code
        if response.status_code not in [200, 201, 302]:
            return False

        # Check for success indicators in response
        success_indicators = ['success', 'logged in', 'authenticated', 'token', 'session']
        error_indicators = ['error', 'invalid', 'failed', 'incorrect', 'denied']

        response_text = response.text.lower()

        # If we find error indicators, login failed
        if any(error in response_text for error in error_indicators):
            return False

        # If we find success indicators or got cookies, likely successful
        if (any(success in response_text for success in success_indicators) or
                response.cookies or
                response.status_code == 302):  # Redirect often indicates success
            return True

        # Test with a protected endpoint if available
        return self._test_authentication()

    def _test_authentication(self) -> bool:
        """Test if current authentication is working"""
        # Try a few common protected endpoints
        test_endpoints = [
            '/me', '/user', '/profile', '/account',
            '/api/me', '/api/user', '/api/profile',
            '/admin', '/dashboard', '/settings'
        ]

        for endpoint in test_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=5)

                # If we get 200 or 403 (forbidden but authenticated), auth is working
                # 401 means authentication failed
                if response.status_code in [200, 403]:
                    return True
                elif response.status_code == 401:
                    return False

            except Exception:
                continue

        # If we can't test, assume it's working
        return True

    def discover_endpoints(self, paths: List[str] = None) -> List[str]:
        """Discover API endpoints through multiple comprehensive methods"""
        logger.info("Starting COMPREHENSIVE endpoint discovery...")

        discovered = set()

        # Method 1: Try common API documentation endpoints
        doc_endpoints = [
            '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api-docs.json', '/docs', '/documentation',
            '/swagger-ui.html', '/redoc', '/graphql', '/api/v1', '/api/v2',
            '/health', '/status', '/ping', '/info', '/metrics'
        ]

        discovered.update(self._discover_from_documentation())
        discovered.update(self._discover_from_common_paths(doc_endpoints))

        # Method 2: Try provided paths
        if paths:
            discovered.update(self._test_provided_paths(paths))

        # Method 3: Comprehensive pattern discovery
        discovered.update(self._discover_from_patterns())

        # Method 4: Common files and configurations
        discovered.update(self._discover_common_files())

        # Method 5: Basic infrastructure discovery
        discovered.update(self._discover_from_robots_txt())
        discovered.update(self._discover_from_sitemap())

        # Method 6: Advanced discovery techniques (if deep scan enabled)
        if self.deep_scan:
            logger.info("Deep scan enabled - running advanced discovery methods...")
            discovered.update(self._discover_from_dns_and_subdomains())
            discovered.update(self._discover_from_certificates())
            discovered.update(self._discover_from_wayback_machine())
            discovered.update(self._discover_from_github_search())
            discovered.update(self._discover_from_social_media())
            discovered.update(self._discover_from_error_pages())
            discovered.update(self._discover_framework_specific())

        # Method 7: Content-type specific discovery
        discovered.update(self._discover_from_content_analysis(list(discovered)))

        # Method 8: Response analysis for additional endpoints
        discovered.update(self._discover_from_responses(list(discovered)))

        logger.info(f"Discovered {len(discovered)} unique endpoints using comprehensive methods")
        return list(discovered)

    def _discover_from_documentation(self) -> Set[str]:
        """Try to discover endpoints from API documentation"""
        discovered = set()

        doc_urls = [
            f"{self.base_url}/swagger.json",
            f"{self.base_url}/openapi.json",
            f"{self.base_url}/api-docs",
            f"{self.base_url}/v2/api-docs"
        ]

        for doc_url in doc_urls:
            try:
                response = self.session.get(doc_url, timeout=10)
                if response.status_code == 200:
                    logger.info(f"Found API documentation at {doc_url}")
                    discovered.update(self._parse_openapi_spec(response.json()))
                    break
            except Exception as e:
                logger.debug(f"Could not fetch {doc_url}: {e}")

        return discovered

    def _parse_openapi_spec(self, spec: Dict) -> Set[str]:
        """Parse OpenAPI/Swagger specification"""
        discovered = set()

        try:
            if 'paths' in spec:
                for path, methods in spec['paths'].items():
                    discovered.add(path)
                    logger.debug(f"Found documented endpoint: {path}")
        except Exception as e:
            logger.error(f"Error parsing OpenAPI spec: {e}")

        return discovered

    def _discover_from_common_paths(self, paths: List[str]) -> Set[str]:
        """Test common API paths"""
        discovered = set()

        common_patterns = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/users', '/user', '/admin', '/auth', '/login',
            '/products', '/orders', '/items', '/data',
            '/search', '/query', '/list', '/get', '/post',
            '/health', '/status', '/ping', '/info'
        ]

        all_paths = paths + common_patterns

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {
                executor.submit(self._test_path, path): path
                for path in all_paths
            }

            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    if future.result():
                        discovered.add(path)
                        logger.debug(f"Discovered endpoint: {path}")
                except Exception as e:
                    logger.debug(f"Error testing {path}: {e}")

        return discovered

    def _test_provided_paths(self, paths: List[str]) -> Set[str]:
        """Test user-provided paths"""
        discovered = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {
                executor.submit(self._test_path, path): path
                for path in paths
            }

            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    if future.result():
                        discovered.add(path)
                except Exception as e:
                    logger.debug(f"Error testing {path}: {e}")

        return discovered

    def _test_path(self, path: str) -> bool:
        """Test if a path exists and is accessible"""
        try:
            url = urljoin(self.base_url, path)
            response = self.session.get(url, timeout=10, allow_redirects=False)

            # Consider 2xx, 3xx, 4xx as valid (but not 5xx)
            if response.status_code < 500:
                return True

        except Exception as e:
            logger.debug(f"Path test failed for {path}: {e}")

        return False

    def _discover_from_patterns(self) -> Set[str]:
        """Discover endpoints using comprehensive patterns - MAXIMUM COVERAGE"""
        discovered = set()

        # COMPREHENSIVE resource patterns - 200+ patterns
        resource_patterns = [
            # Primary resources
            'users', 'user', 'accounts', 'account', 'customers', 'customer',
            'products', 'product', 'items', 'item', 'goods', 'catalog',
            'orders', 'order', 'purchases', 'purchase', 'transactions', 'transaction',
            'payments', 'payment', 'billing', 'invoices', 'invoice',
            'categories', 'category', 'tags', 'tag', 'labels', 'label',
            'posts', 'post', 'articles', 'article', 'blogs', 'blog',
            'comments', 'comment', 'reviews', 'review', 'ratings', 'rating',
            'files', 'file', 'documents', 'document', 'attachments', 'attachment',
            'images', 'image', 'photos', 'photo', 'media', 'assets',
            'videos', 'video', 'audio', 'music', 'podcasts', 'podcast',
            'groups', 'group', 'teams', 'team', 'organizations', 'organization',
            'roles', 'role', 'permissions', 'permission', 'rights', 'privileges',
            'sessions', 'session', 'tokens', 'token', 'keys', 'credentials',
            'notifications', 'notification', 'alerts', 'alert', 'messages', 'message',
            'events', 'event', 'activities', 'activity', 'logs', 'log',
            'reports', 'report', 'analytics', 'stats', 'statistics', 'metrics',
            'settings', 'config', 'configuration', 'preferences', 'options',
            'feeds', 'feed', 'streams', 'stream', 'channels', 'channel',
            'subscriptions', 'subscription', 'plans', 'plan', 'packages', 'package',
            'campaigns', 'campaign', 'promotions', 'promotion', 'offers', 'offer',
            'coupons', 'coupon', 'discounts', 'discount', 'deals', 'deal',
            'bookings', 'booking', 'reservations', 'reservation', 'appointments', 'appointment',
            'tickets', 'ticket', 'issues', 'issue', 'requests', 'request',
            'surveys', 'survey', 'forms', 'form', 'questionnaires', 'questionnaire',
            'contacts', 'contact', 'leads', 'lead', 'prospects', 'prospect',
            'vendors', 'vendor', 'suppliers', 'supplier', 'partners', 'partner',
            'locations', 'location', 'addresses', 'address', 'places', 'place',
            'devices', 'device', 'sensors', 'sensor', 'machines', 'machine',
            'workflows', 'workflow', 'processes', 'process', 'jobs', 'job',
            'queues', 'queue', 'tasks', 'task', 'todos', 'todo',
            'projects', 'project', 'milestones', 'milestone', 'goals', 'goal'
        ]

        # Extended API versioning patterns
        version_patterns = [
            'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10',
            'version1', 'version2', 'version3', 'version4', 'version5',
            '1.0', '1.1', '1.2', '2.0', '2.1', '3.0', '3.1', '4.0',
            '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
            'latest', 'current', 'stable', 'release', 'production', 'prod',
            'beta', 'alpha', 'preview', 'dev', 'development', 'test'
        ]

        # Comprehensive API base patterns
        api_bases = [
            'api', 'rest', 'restapi', 'webapi', 'service', 'services',
            'gateway', 'proxy', 'backend', 'server', 'app', 'application',
            'web', 'mobile', 'public', 'private', 'internal', 'external',
            'core', 'main', 'primary', 'secondary', 'admin', 'management'
        ]

        # Generate comprehensive path combinations
        patterns = []

        logger.info(
            f"Generating patterns from {len(resource_patterns)} resources, {len(version_patterns)} versions, {len(api_bases)} bases...")

        # 1. Basic resource patterns
        for resource in resource_patterns:
            patterns.extend([
                f"/{resource}",
                f"/{resource}s" if not resource.endswith('s') else f"/{resource[:-1]}",
            ])

        # 2. API base + resource combinations  
        for base in api_bases:
            for resource in resource_patterns[:50]:  # Limit to avoid explosion
                patterns.extend([
                    f"/{base}/{resource}",
                    f"/{base}/{resource}s" if not resource.endswith('s') else f"/{base}/{resource[:-1]}",
                ])

        # 3. Versioned API patterns
        for base in api_bases[:10]:  # Limit bases
            for version in version_patterns[:10]:  # Limit versions  
                patterns.extend([
                    f"/{base}/{version}",
                    f"/{version}/{base}",
                    f"/{version}",
                ])

                # Add resources to versioned APIs
                for resource in resource_patterns[:30]:  # Limit resources
                    patterns.extend([
                        f"/{base}/{version}/{resource}",
                        f"/{version}/{base}/{resource}",
                        f"/{version}/{resource}",
                    ])

        logger.info(f"Generated {len(patterns)} total patterns for comprehensive discovery")

        return self._discover_from_common_paths(patterns)

    def _discover_common_files(self) -> Set[str]:
        """Discover common files that might reveal API information"""
        common_files = [
            # Configuration files
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/config.json', '/config.yaml', '/config.yml', '/config.xml',
            '/package.json', '/composer.json', '/requirements.txt',

            # Documentation files
            '/README.md', '/API.md', '/docs.json', '/docs.yaml',
            '/swagger.yaml', '/swagger.yml', '/openapi.yaml', '/openapi.yml',

            # Security files
            '/.well-known/security.txt', '/security.txt', '/.well-known/openid_configuration',
            '/.well-known/jwks.json', '/.well-known/oauth-authorization-server',

            # API specific files
            '/api.json', '/api.yaml', '/endpoints.json', '/routes.json', '/paths.json',
            '/schema.json', '/schema.yaml', '/postman.json', '/collection.json'
        ]

        return self._test_file_list(common_files)

    def _test_file_list(self, file_list: List[str]) -> Set[str]:
        """Test a list of files for existence"""
        discovered = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self._test_path, file_path): file_path
                for file_path in file_list
            }

            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    if future.result():
                        discovered.add(file_path)
                        logger.debug(f"Found accessible file: {file_path}")
                except Exception as e:
                    logger.debug(f"Error testing {file_path}: {e}")

        return discovered

    def _discover_from_robots_txt(self) -> Set[str]:
        """Discover endpoints from robots.txt"""
        discovered = set()

        try:
            robots_url = f"{self.base_url}/robots.txt"
            response = self.session.get(robots_url, timeout=10)

            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if 'Disallow:' in line or 'Allow:' in line:
                        path = line.split(':', 1)[1].strip()
                        if path and path.startswith('/'):
                            discovered.add(path)

        except Exception as e:
            logger.debug(f"Could not fetch robots.txt: {e}")

        return discovered

    def _discover_from_sitemap(self) -> Set[str]:
        """Discover endpoints from sitemap.xml"""
        discovered = set()

        try:
            sitemap_url = f"{self.base_url}/sitemap.xml"
            response = self.session.get(sitemap_url, timeout=10)

            if response.status_code == 200:
                root = ET.fromstring(response.text)
                for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                    loc_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                    if loc_elem is not None:
                        path = urlparse(loc_elem.text).path
                        if path:
                            discovered.add(path)

        except Exception as e:
            logger.debug(f"Could not fetch sitemap.xml: {e}")

        return discovered

    def _discover_from_dns_and_subdomains(self) -> Set[str]:
        """Discover endpoints from DNS and subdomain analysis"""
        discovered = set()

        try:
            parsed_url = urlparse(self.base_url)
            domain = parsed_url.netloc

            # API subdomain patterns
            api_subdomains = [
                'api', 'rest', 'webapi', 'service', 'services',
                'gateway', 'proxy', 'backend', 'server',
                'v1', 'v2', 'v3', 'staging', 'dev', 'test',
                'mobile', 'web', 'public', 'private', 'secure'
            ]

            for subdomain in api_subdomains:
                subdomain_url = f"{parsed_url.scheme}://{subdomain}.{domain}"
                try:
                    response = self.session.get(subdomain_url, timeout=5)
                    if response.status_code < 500:
                        discovered.update(['/api', '/v1', '/health', '/docs'])
                        logger.debug(f"Found active subdomain: {subdomain}.{domain}")
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"DNS discovery error: {e}")

        return discovered

    def _discover_from_certificates(self) -> Set[str]:
        """Discover endpoints from SSL certificate analysis"""
        discovered = set()

        if not self.base_url.startswith('https://'):
            return discovered

        try:
            import ssl
            import socket

            parsed_url = urlparse(self.base_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443

            # Get SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Extract Subject Alternative Names
                    if 'subjectAltName' in cert:
                        for name_type, name_value in cert['subjectAltName']:
                            if name_type == 'DNS':
                                if any(api_term in name_value.lower() for api_term in ['api', 'rest', 'service']):
                                    discovered.update(['/api', '/v1', '/health', '/docs'])
                                    logger.debug(f"Found API-related certificate SAN: {name_value}")

        except Exception as e:
            logger.debug(f"Certificate analysis error: {e}")

        return discovered

    def _discover_from_wayback_machine(self) -> Set[str]:
        """Discover historical endpoints from Wayback Machine"""
        discovered = set()

        try:
            from urllib.parse import quote
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={quote(self.base_url)}/*&output=json&limit=100"

            response = self.session.get(wayback_url, timeout=15)
            if response.status_code == 200:
                data = response.json()

                for entry in data[1:]:  # Skip header row
                    if len(entry) > 2:
                        archived_url = entry[2]
                        parsed = urlparse(archived_url)
                        if parsed.path and parsed.path != '/':
                            clean_path = parsed.path.split('?')[0]
                            discovered.add(clean_path)

                logger.debug(f"Wayback Machine found {len(discovered)} historical endpoints")

        except Exception as e:
            logger.debug(f"Wayback Machine discovery error: {e}")

        return discovered

    def _discover_from_github_search(self) -> Set[str]:
        """Discover endpoints from GitHub search"""
        discovered = set()

        try:
            from urllib.parse import quote
            domain = urlparse(self.base_url).netloc

            github_search_url = f"https://api.github.com/search/code?q={quote(domain)}+path:*.json"

            response = self.session.get(github_search_url, timeout=10)
            if response.status_code == 200:
                data = response.json()

                for item in data.get('items', [])[:10]:
                    if 'api' in item.get('name', '').lower():
                        discovered.update(['/api/v1', '/api/v2', '/rest', '/graphql'])

                logger.debug(f"GitHub search suggested {len(discovered)} potential endpoints")

        except Exception as e:
            logger.debug(f"GitHub search error: {e}")

        return discovered

    def _discover_from_social_media(self) -> Set[str]:
        """Discover endpoints from social media and public documentation"""
        discovered = set()
        # Placeholder for social media discovery
        return discovered

    def _discover_from_error_pages(self) -> Set[str]:
        """Discover endpoints by analyzing error pages"""
        discovered = set()

        error_test_paths = [
            '/nonexistent-endpoint-12345',
            '/api/nonexistent',
            '/v1/invalid',
            '/admin/test404'
        ]

        for path in error_test_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=5)

                if response.status_code >= 400:
                    content = response.text.lower()

                    endpoint_patterns = [
                        r'available endpoints?:?\s*([^\n]+)',
                        r'valid paths?:?\s*([^\n]+)',
                        r'try:?\s*(/[^\s\n]+)'
                    ]

                    for pattern in endpoint_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if isinstance(match, str) and match.startswith('/'):
                                discovered.add(match.split()[0])

            except Exception as e:
                logger.debug(f"Error page analysis failed for {path}: {e}")

        return discovered

    def _discover_framework_specific(self) -> Set[str]:
        """Discover framework-specific endpoints"""
        discovered = set()

        framework_endpoints = {
            'spring_boot': [
                '/actuator', '/actuator/health', '/actuator/info', '/actuator/metrics'
            ],
            'django': [
                '/admin/', '/api/', '/api/v1/', '/accounts/', '/auth/'
            ],
            'flask': [
                '/api/', '/admin/', '/auth/', '/static/', '/health'
            ],
            'fastapi': [
                '/docs', '/redoc', '/openapi.json', '/health', '/api/v1'
            ],
            'express': [
                '/api/', '/health', '/status', '/metrics', '/admin'
            ]
        }

        detected_frameworks = []

        for framework, endpoints in framework_endpoints.items():
            test_endpoints = endpoints[:2]
            found_count = 0

            for endpoint in test_endpoints:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = self.session.head(url, timeout=5)
                    if response.status_code < 500:
                        found_count += 1
                except Exception:
                    pass

            if found_count >= 1:
                detected_frameworks.append(framework)
                discovered.update(endpoints)
                logger.info(f"Detected framework: {framework}")

        return discovered

    def _discover_from_content_analysis(self, known_endpoints: List[str]) -> Set[str]:
        """Advanced content analysis for endpoint discovery"""
        discovered = set()

        for endpoint in known_endpoints[:5]:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=10)

                if response.status_code == 200:
                    content = response.text
                    content_type = response.headers.get('Content-Type', '').lower()

                    if 'javascript' in content_type:
                        discovered.update(self._discover_from_javascript(content))
                    elif 'html' in content_type:
                        discovered.update(self._discover_from_html_forms(content))
                    elif 'json' in content_type:
                        try:
                            json_data = response.json()
                            discovered.update(self._discover_from_json_structure(json_data))
                        except Exception:
                            pass

            except Exception as e:
                logger.debug(f"Content analysis error for {endpoint}: {e}")

        return discovered

    def _discover_from_javascript(self, content: str) -> Set[str]:
        """Discover endpoints from JavaScript code"""
        discovered = set()

        js_patterns = [
            r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'axios\.get\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'axios\.post\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'\$\.ajax\s*\([^{]*{[^}]*url\s*:\s*[`"\']([^`"\']+)[`"\']',
            r'const\s+\w*[Uu]rl\s*=\s*[`"\']([^`"\']+)[`"\']'
        ]

        for pattern in js_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]

                    if match and match.startswith('/'):
                        clean_path = re.sub(r'\$\{[^}]+\}', '{id}', match)
                        discovered.add(clean_path)

            except re.error:
                continue

        return discovered

    def _discover_from_html_forms(self, content: str) -> Set[str]:
        """Discover endpoints from HTML forms"""
        discovered = set()

        form_patterns = [
            r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']',
            r'<input[^>]+formaction\s*=\s*["\']([^"\']+)["\']'
        ]

        for pattern in form_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match and match.startswith('/'):
                    discovered.add(match.split('?')[0])

        return discovered

    def _discover_from_json_structure(self, json_data: any) -> Set[str]:
        """Discover endpoints from JSON structure analysis"""
        discovered = set()

        def extract_paths(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if any(url_key in key.lower() for url_key in ['url', 'href', 'link', 'endpoint', 'path']):
                        if isinstance(value, str) and value.startswith('/'):
                            discovered.add(value.split('?')[0])

                    if isinstance(value, (dict, list)):
                        extract_paths(value)

            elif isinstance(obj, list):
                for item in obj[:3]:
                    extract_paths(item)

        try:
            extract_paths(json_data)
        except Exception as e:
            logger.debug(f"JSON structure analysis error: {e}")

        return discovered

    def _discover_from_responses(self, known_endpoints: List[str]) -> Set[str]:
        """Discover additional endpoints from response content"""
        discovered = set()

        url_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'href=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']'
        ]

        for endpoint in known_endpoints[:10]:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=10)

                if response.status_code == 200:
                    content = response.text

                    for pattern in url_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if match.startswith('/') and not match.startswith('//'):
                                path = match.split('?')[0].split('#')[0]
                                if len(path) > 1 and len(path) < 200:
                                    discovered.add(path)

            except Exception as e:
                logger.debug(f"Error analyzing response from {endpoint}: {e}")

        # Clean up discovered paths
        cleaned_discovered = set()
        for path in discovered:
            if (path and path.startswith('/') and len(path) > 1 and len(path) < 200 and
                    not any(skip in path.lower() for skip in [
                        'javascript:', 'mailto:', '.css', '.js', '.png', '.jpg', '.gif'
                    ])):
                cleaned_discovered.add(path)

        return cleaned_discovered

    def analyze_endpoint(self, path: str, methods: List[str] = None) -> List[APIEndpoint]:
        """Analyze a specific endpoint with multiple HTTP methods"""
        if methods is None:
            methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

        endpoints = []

        for method in methods:
            try:
                endpoint_data = self._test_endpoint_method(path, method)
                if endpoint_data:
                    endpoints.append(endpoint_data)

                time.sleep(self.rate_limit_delay)

            except Exception as e:
                logger.debug(f"Error testing {method} {path}: {e}")

        return endpoints

    def _test_endpoint_method(self, path: str, method: str) -> Optional[APIEndpoint]:
        """Test a specific endpoint with a specific HTTP method"""
        url = urljoin(self.base_url, path)

        try:
            start_time = time.time()

            kwargs = {
                'timeout': self.timeout,
                'allow_redirects': self.follow_redirects
            }

            if method in ['POST', 'PUT', 'PATCH']:
                kwargs['json'] = self._generate_test_payload(path)

            response = self.session.request(method, url, **kwargs)
            response_time = time.time() - start_time

            parameters = self._extract_parameters(path, response, method)
            schema = self._analyze_response_schema(response)

            endpoint = APIEndpoint(
                path=path,
                method=method,
                parameters=parameters,
                headers=dict(response.request.headers),
                status_code=response.status_code,
                response_time=response_time,
                response_body=response.text[:1000],
                response_headers=dict(response.headers),
                content_type=response.headers.get('Content-Type', ''),
                schema=schema
            )

            with self.lock:
                self._update_stats(endpoint)

            logger.debug(f"{method} {path} -> {response.status_code} ({response_time:.3f}s)")

            return endpoint

        except Exception as e:
            logger.debug(f"Error testing {method} {path}: {e}")
            return APIEndpoint(
                path=path,
                method=method,
                parameters={},
                headers={},
                status_code=0,
                response_time=0,
                response_body='',
                response_headers={},
                content_type='',
                error=str(e)
            )

    def _generate_test_payload(self, path: str) -> Dict[str, Any]:
        """Generate a test payload for POST/PUT/PATCH requests"""
        if 'user' in path.lower():
            return {"name": "Test User", "email": "test@example.com", "id": 12345}
        elif 'product' in path.lower():
            return {"name": "Test Product", "price": 99.99, "id": 12345}
        elif 'order' in path.lower():
            return {"user_id": 12345, "product_id": 67890, "quantity": 1}
        else:
            return {"id": 12345, "name": "Test Item", "value": "test_value"}

    def _extract_parameters(self, path: str, response: requests.Response, method: str) -> Dict[str, Any]:
        """Extract parameters from path, query, headers, and response"""
        parameters = {
            'path_parameters': [],
            'query_parameters': [],
            'header_parameters': [],
            'body_parameters': [],
            'response_fields': []
        }

        path_params = re.findall(r'\{([^}]+)\}', path)
        parameters['path_parameters'] = path_params

        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        parameters['query_parameters'] = list(query_params.keys())

        common_headers = [
            'Authorization', 'X-API-Key', 'X-Auth-Token', 'X-Request-ID',
            'X-Correlation-ID', 'X-Tenant-ID', 'X-User-ID'
        ]
        parameters['header_parameters'] = [h for h in common_headers if h in response.request.headers]

        try:
            if response.headers.get('Content-Type', '').startswith('application/json'):
                json_data = response.json()
                if isinstance(json_data, dict):
                    parameters['response_fields'] = list(json_data.keys())
                elif isinstance(json_data, list) and json_data and isinstance(json_data[0], dict):
                    parameters['response_fields'] = list(json_data[0].keys())
        except Exception:
            pass

        return parameters

    def _analyze_response_schema(self, response: requests.Response) -> Optional[Dict]:
        """Analyze response to infer schema"""
        try:
            if response.headers.get('Content-Type', '').startswith('application/json'):
                json_data = response.json()
                return self._infer_json_schema(json_data)
        except Exception:
            pass

        return None

    def _infer_json_schema(self, data: Any, max_depth: int = 3) -> Dict:
        """Infer JSON schema from data"""
        if max_depth <= 0:
            return {"type": "object"}

        if isinstance(data, dict):
            properties = {}
            for key, value in data.items():
                properties[key] = self._infer_json_schema(value, max_depth - 1)
            return {"type": "object", "properties": properties}
        elif isinstance(data, list):
            if data:
                item_schema = self._infer_json_schema(data[0], max_depth - 1)
            else:
                item_schema = {"type": "string"}
            return {"type": "array", "items": item_schema}
        elif isinstance(data, str):
            return {"type": "string"}
        elif isinstance(data, int):
            return {"type": "integer"}
        elif isinstance(data, float):
            return {"type": "number"}
        elif isinstance(data, bool):
            return {"type": "boolean"}
        else:
            return {"type": "string"}

    def _update_stats(self, endpoint: APIEndpoint):
        """Update performance and error statistics"""
        key = f"{endpoint.method}_{endpoint.path}"
        if key not in self.performance_stats:
            self.performance_stats[key] = []
        self.performance_stats[key].append(endpoint.response_time)

        if endpoint.status_code >= 400:
            self.error_patterns[endpoint.status_code].append(endpoint.path)

    def scan_comprehensive(self, custom_paths: List[str] = None) -> APIAnalysis:
        """Perform comprehensive API scan"""
        logger.info(f"Starting comprehensive scan of {self.base_url}")

        discovered_paths = self.discover_endpoints(custom_paths)
        all_endpoints = []

        logger.info(f"Analyzing {len(discovered_paths)} discovered endpoints...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {
                executor.submit(self.analyze_endpoint, path): path
                for path in discovered_paths
            }

            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    endpoints = future.result()
                    all_endpoints.extend(endpoints)
                    logger.debug(f"Analyzed {path}: {len(endpoints)} methods")
                except Exception as e:
                    logger.error(f"Error analyzing {path}: {e}")

        self._analyze_patterns(all_endpoints)
        self._security_analysis(all_endpoints)

        analysis = APIAnalysis(
            base_url=self.base_url,
            discovered_endpoints=all_endpoints,
            parameter_patterns=dict(self.parameter_patterns),
            authentication_methods=self._detect_auth_methods(all_endpoints),
            error_patterns=dict(self.error_patterns),
            rate_limits=self.rate_limits,
            security_findings=self.security_findings,
            performance_stats=self._calculate_performance_stats()
        )

        logger.info(f"Scan complete: {len(all_endpoints)} total endpoint/method combinations analyzed")

        return analysis

    def _analyze_patterns(self, endpoints: List[APIEndpoint]):
        """Analyze patterns in parameters and responses"""
        for endpoint in endpoints:
            for param_type, params in endpoint.parameters.items():
                self.parameter_patterns[param_type].extend(params)

    def _security_analysis(self, endpoints: List[APIEndpoint]):
        """Perform basic security analysis"""
        findings = []

        # Check for common security headers
        security_headers = [
            'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Content-Security-Policy'
        ]

        missing_headers = set(security_headers)
        for endpoint in endpoints:
            for header in security_headers:
                if header in endpoint.response_headers:
                    missing_headers.discard(header)

        if missing_headers:
            findings.append(f"Missing security headers: {', '.join(missing_headers)}")

        # Check for exposed sensitive endpoints
        sensitive_patterns = [
            'admin', 'debug', 'test', 'internal', 'private',
            'config', 'env', 'secret', 'key', 'token'
        ]

        exposed_sensitive = []
        for endpoint in endpoints:
            for pattern in sensitive_patterns:
                if pattern in endpoint.path.lower() and endpoint.status_code < 400:
                    exposed_sensitive.append(endpoint.path)

        if exposed_sensitive:
            findings.append(f"Potentially sensitive endpoints exposed: {', '.join(set(exposed_sensitive))}")

        # Check for verbose error messages
        verbose_errors = []
        for endpoint in endpoints:
            if endpoint.status_code >= 500:
                if any(keyword in endpoint.response_body.lower() for keyword in
                       ['stack', 'trace', 'exception', 'error']):
                    verbose_errors.append(endpoint.path)

        if verbose_errors:
            findings.append(f"Endpoints with verbose error messages: {', '.join(set(verbose_errors))}")

        self.security_findings = findings

    def _detect_auth_methods(self, endpoints: List[APIEndpoint]) -> List[str]:
        """Detect authentication methods used by the API"""
        auth_methods = set()

        for endpoint in endpoints:
            # Check headers
            if 'Authorization' in endpoint.headers:
                auth_value = endpoint.headers['Authorization']
                if auth_value.startswith('Bearer'):
                    auth_methods.add('Bearer Token')
                elif auth_value.startswith('Basic'):
                    auth_methods.add('Basic Auth')
                else:
                    auth_methods.add('Custom Authorization')

            # Check for API key patterns
            for header in endpoint.headers:
                if 'api' in header.lower() and 'key' in header.lower():
                    auth_methods.add('API Key')

            # Check response for authentication challenges
            if endpoint.status_code == 401:
                www_auth = endpoint.response_headers.get('WWW-Authenticate', '')
                if 'Bearer' in www_auth:
                    auth_methods.add('OAuth/Bearer')
                elif 'Basic' in www_auth:
                    auth_methods.add('Basic Auth')

        return list(auth_methods)

    def _calculate_performance_stats(self) -> Dict[str, float]:
        """Calculate performance statistics"""
        stats = {}

        for endpoint, times in self.performance_stats.items():
            if times:
                stats[f"{endpoint}_avg"] = sum(times) / len(times)
                stats[f"{endpoint}_min"] = min(times)
                stats[f"{endpoint}_max"] = max(times)

        return stats

    def generate_swagger_builder_format(self, analysis: APIAnalysis, output_file: str):
        """Generate enhanced format optimized for Swagger documentation building"""
        swagger_data = {
            "openapi": "3.0.3",
            "info": {
                "title": f"API Documentation - {urlparse(self.base_url).netloc}",
                "description": f"Auto-discovered API documentation for {self.base_url}",
                "version": "1.0.0",
                "contact": {
                    "name": "API Scanner",
                    "url": "https://github.com/your-repo/universal-api-scanner"
                },
                "license": {
                    "name": "MIT",
                    "url": "https://opensource.org/licenses/MIT"
                }
            },
            "servers": [
                {
                    "url": self.base_url,
                    "description": "Discovered API Server"
                }
            ],
            "security": self._generate_security_schemes(analysis),
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": self._generate_security_schemes_components(analysis),
                "parameters": self._generate_common_parameters(analysis),
                "responses": self._generate_common_responses(analysis),
                "examples": {}
            },
            "tags": self._generate_tags(analysis),
            "x-scanner-metadata": {
                "scan_date": datetime.now().isoformat(),
                "total_endpoints": len(analysis.discovered_endpoints),
                "authentication_methods": analysis.authentication_methods,
                "security_findings": analysis.security_findings,
                "performance_summary": self._get_performance_summary(analysis)
            }
        }

        # Group endpoints by path for better organization
        paths_by_route = defaultdict(list)
        for endpoint in analysis.discovered_endpoints:
            if endpoint.status_code > 0:  # Only include valid endpoints
                paths_by_route[endpoint.path].append(endpoint)

        # Process each path
        for path, endpoints in paths_by_route.items():
            swagger_data["paths"][path] = self._generate_path_item(path, endpoints)

            # Generate schemas from successful responses
            for endpoint in endpoints:
                if endpoint.schema and endpoint.status_code < 400:
                    schema_name = self._generate_schema_name(endpoint.path, endpoint.method)
                    swagger_data["components"]["schemas"][schema_name] = endpoint.schema

                # Generate examples from responses
                if endpoint.response_body and endpoint.status_code < 400:
                    example_name = f"{endpoint.method}_{self._sanitize_name(endpoint.path)}_example"
                    try:
                        if endpoint.content_type.startswith('application/json'):
                            swagger_data["components"]["examples"][example_name] = {
                                "summary": f"Example response for {endpoint.method} {endpoint.path}",
                                "value": json.loads(endpoint.response_body)
                            }
                    except json.JSONDecodeError:
                        pass

        # Save the enhanced Swagger documentation
        with open(output_file, 'w') as f:
            yaml.dump(swagger_data, f, default_flow_style=False, sort_keys=False, indent=2)

        logger.info(f"Swagger builder format saved to {output_file}")

        # Also generate a companion JSON file with additional metadata
        json_output = output_file.replace('.yaml', '.json').replace('.yml', '.json')
        with open(json_output, 'w') as f:
            json.dump(swagger_data, f, indent=2, default=str)

        logger.info(f"JSON format also saved to {json_output}")

        return swagger_data

    def _generate_path_item(self, path: str, endpoints: List[APIEndpoint]) -> Dict:
        """Generate OpenAPI path item for a specific path"""
        path_item = {
            "summary": f"Operations for {path}",
            "description": f"Auto-discovered operations for the {path} endpoint"
        }

        # Add path parameters if detected
        path_params = self._extract_path_parameters(path, endpoints)
        if path_params:
            path_item["parameters"] = path_params

        # Process each HTTP method
        for endpoint in endpoints:
            if endpoint.status_code > 0:
                method_lower = endpoint.method.lower()
                path_item[method_lower] = self._generate_operation(endpoint)

        return path_item

    def _generate_operation(self, endpoint: APIEndpoint) -> Dict:
        """Generate OpenAPI operation object for an endpoint"""
        operation = {
            "operationId": f"{endpoint.method.lower()}_{self._sanitize_name(endpoint.path)}",
            "summary": f"{endpoint.method} {endpoint.path}",
            "description": self._generate_operation_description(endpoint),
            "tags": self._determine_tags(endpoint.path),
            "responses": self._generate_responses(endpoint)
        }

        # Add parameters
        parameters = []

        # Path parameters
        for param in endpoint.parameters.get('path_parameters', []):
            parameters.append({
                "name": param,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": f"Path parameter {param}"
            })

        # Query parameters
        for param in endpoint.parameters.get('query_parameters', []):
            parameters.append({
                "name": param,
                "in": "query",
                "required": False,
                "schema": {"type": "string"},
                "description": f"Query parameter {param}"
            })

        # Header parameters (except auth headers)
        auth_headers = ['authorization', 'x-api-key', 'x-auth-token']
        for param in endpoint.parameters.get('header_parameters', []):
            if param.lower() not in auth_headers:
                parameters.append({
                    "name": param,
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                    "description": f"Header parameter {param}"
                })

        if parameters:
            operation["parameters"] = parameters

        # Add request body for POST/PUT/PATCH methods
        if endpoint.method in ['POST', 'PUT', 'PATCH']:
            operation["requestBody"] = self._generate_request_body(endpoint)

        # Add security requirements
        if self._requires_authentication(endpoint):
            operation["security"] = self._get_security_requirements(endpoint)

        # Add metadata
        operation["x-scanner-data"] = {
            "status_code": endpoint.status_code,
            "response_time": endpoint.response_time,
            "content_type": endpoint.content_type,
            "discovered_at": datetime.now().isoformat()
        }

        return operation

    def _generate_operation_description(self, endpoint: APIEndpoint) -> str:
        """Generate descriptive text for an operation"""
        descriptions = []

        # Basic description
        resource = self._extract_resource_name(endpoint.path)
        action = self._infer_action(endpoint.method, endpoint.path)
        descriptions.append(f"{action} {resource}")

        # Add status code info
        if endpoint.status_code < 400:
            descriptions.append(f"Returns {endpoint.status_code} on success.")
        else:
            descriptions.append(f"May return {endpoint.status_code} status.")

        # Add authentication requirement
        if self._requires_authentication(endpoint):
            descriptions.append("Requires authentication.")

        # Add performance note
        if endpoint.response_time > 2.0:
            descriptions.append(f"Note: Slower response time ({endpoint.response_time:.1f}s observed).")

        return " ".join(descriptions)

    def _generate_responses(self, endpoint: APIEndpoint) -> Dict:
        """Generate OpenAPI responses for an endpoint"""
        responses = {}

        # Main response based on observed status code
        if endpoint.status_code > 0:
            response_obj = {
                "description": self._get_status_description(endpoint.status_code)
            }

            # Add content if we have a schema or example
            if endpoint.schema or endpoint.response_body:
                content = {}

                if endpoint.content_type:
                    media_type = endpoint.content_type.split(';')[0].strip()
                    content[media_type] = {}

                    if endpoint.schema:
                        content[media_type]["schema"] = endpoint.schema

                    if endpoint.response_body and media_type == 'application/json':
                        try:
                            example_data = json.loads(endpoint.response_body)
                            content[media_type]["example"] = example_data
                        except json.JSONDecodeError:
                            pass

                if content:
                    response_obj["content"] = content

            responses[str(endpoint.status_code)] = response_obj

        # Add common error responses if not already present
        common_errors = {
            "400": "Bad Request - Invalid input parameters",
            "401": "Unauthorized - Authentication required",
            "403": "Forbidden - Insufficient permissions",
            "404": "Not Found - Resource not found",
            "500": "Internal Server Error - Server error occurred"
        }

        for status, description in common_errors.items():
            if status not in responses and (endpoint.status_code < 400 or status == str(endpoint.status_code)):
                responses[status] = {"description": description}

        return responses

    def _generate_request_body(self, endpoint: APIEndpoint) -> Dict:
        """Generate request body specification"""
        request_body = {
            "description": f"Request body for {endpoint.method} {endpoint.path}",
            "required": endpoint.method in ['POST', 'PUT'],
            "content": {
                "application/json": {
                    "schema": self._generate_request_schema(endpoint)
                }
            }
        }

        # Add example based on test payload
        example_payload = self._generate_test_payload(endpoint.path)
        if example_payload:
            request_body["content"]["application/json"]["example"] = example_payload

        return request_body

    def _generate_request_schema(self, endpoint: APIEndpoint) -> Dict:
        """Generate request schema based on endpoint analysis"""
        # Use response schema as basis, but make it more appropriate for requests
        if endpoint.schema:
            schema = endpoint.schema.copy()

            # Remove read-only fields common in responses
            if "properties" in schema:
                read_only_fields = ['id', 'created_at', 'updated_at', 'created', 'modified']
                for field in read_only_fields:
                    schema["properties"].pop(field, None)

            return schema
        else:
            # Generate generic schema based on path
            return self._generate_generic_schema(endpoint.path)

    def _generate_generic_schema(self, path: str) -> Dict:
        """Generate a generic schema based on the endpoint path"""
        if 'user' in path.lower():
            return {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "User name"},
                    "email": {"type": "string", "format": "email", "description": "User email"},
                    "username": {"type": "string", "description": "Username"}
                },
                "required": ["name", "email"]
            }
        elif 'product' in path.lower():
            return {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Product name"},
                    "price": {"type": "number", "description": "Product price"},
                    "description": {"type": "string", "description": "Product description"}
                },
                "required": ["name", "price"]
            }
        else:
            return {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Item name"},
                    "value": {"type": "string", "description": "Item value"}
                }
            }

    def _generate_security_schemes(self, analysis: APIAnalysis) -> List[Dict]:
        """Generate security requirements for the API"""
        security = []

        for auth_method in analysis.authentication_methods:
            if 'Bearer' in auth_method or 'JWT' in auth_method:
                security.append({"BearerAuth": []})
            elif 'API Key' in auth_method:
                security.append({"ApiKeyAuth": []})
            elif 'Basic' in auth_method:
                security.append({"BasicAuth": []})

        return security if security else [{}]  # Empty object means no security

    def _generate_security_schemes_components(self, analysis: APIAnalysis) -> Dict:
        """Generate security schemes for components section"""
        schemes = {}

        for auth_method in analysis.authentication_methods:
            if 'Bearer' in auth_method or 'JWT' in auth_method:
                schemes["BearerAuth"] = {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "JWT Bearer token authentication"
                }
            elif 'API Key' in auth_method:
                schemes["ApiKeyAuth"] = {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key authentication"
                }
            elif 'Basic' in auth_method:
                schemes["BasicAuth"] = {
                    "type": "http",
                    "scheme": "basic",
                    "description": "HTTP Basic authentication"
                }

        return schemes

    def _generate_common_parameters(self, analysis: APIAnalysis) -> Dict:
        """Generate common parameters that can be reused"""
        parameters = {}

        # Common pagination parameters
        parameters["limitParam"] = {
            "name": "limit",
            "in": "query",
            "description": "Number of items to return",
            "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
        }

        parameters["offsetParam"] = {
            "name": "offset",
            "in": "query",
            "description": "Number of items to skip",
            "schema": {"type": "integer", "minimum": 0, "default": 0}
        }

        # Common filtering parameters
        parameters["sortParam"] = {
            "name": "sort",
            "in": "query",
            "description": "Sort field and direction",
            "schema": {"type": "string", "example": "name:asc"}
        }

        parameters["filterParam"] = {
            "name": "filter",
            "in": "query",
            "description": "Filter expression",
            "schema": {"type": "string"}
        }

        return parameters

    def _generate_common_responses(self, analysis: APIAnalysis) -> Dict:
        """Generate common response definitions"""
        responses = {
            "BadRequest": {
                "description": "Bad Request - Invalid input parameters",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string"},
                                "message": {"type": "string"},
                                "details": {"type": "array", "items": {"type": "string"}}
                            }
                        }
                    }
                }
            },
            "Unauthorized": {
                "description": "Unauthorized - Authentication required",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string", "example": "Unauthorized"},
                                "message": {"type": "string", "example": "Authentication required"}
                            }
                        }
                    }
                }
            },
            "NotFound": {
                "description": "Not Found - Resource not found",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string", "example": "Not Found"},
                                "message": {"type": "string", "example": "Resource not found"}
                            }
                        }
                    }
                }
            }
        }

        return responses

    def _generate_tags(self, analysis: APIAnalysis) -> List[Dict]:
        """Generate tags for grouping operations"""
        tags = []
        tag_names = set()

        # Extract tags from endpoint paths
        for endpoint in analysis.discovered_endpoints:
            tag = self._extract_tag_from_path(endpoint.path)
            if tag and tag not in tag_names:
                tag_names.add(tag)
                tags.append({
                    "name": tag,
                    "description": f"Operations related to {tag}"
                })

        return sorted(tags, key=lambda x: x["name"])

    def _extract_tag_from_path(self, path: str) -> str:
        """Extract a tag name from an endpoint path"""
        # Remove leading slash and split by slash
        parts = path.strip('/').split('/')

        # Skip common prefixes
        skip_parts = ['api', 'rest', 'v1', 'v2', 'v3', 'v4', 'v5']
        filtered_parts = [part for part in parts if part.lower() not in skip_parts]

        if filtered_parts:
            # Use the first meaningful part as tag
            tag = filtered_parts[0]
            # Capitalize and clean up
            return tag.replace('_', ' ').replace('-', ' ').title()

        return "General"

    def _determine_tags(self, path: str) -> List[str]:
        """Determine which tags apply to a specific path"""
        tags = []
        path_lower = path.lower()

        # Extract primary tag
        primary_tag = self._extract_tag_from_path(path)
        if primary_tag:
            tags.append(primary_tag)

        # Add secondary tags based on path content
        if any(auth_term in path_lower for auth_term in ['auth', 'login', 'token', 'session']):
            tags.append("Authentication")
        if any(health_term in path_lower for health_term in ['health', 'status', 'ping', 'info']):
            tags.append("Health")
        if any(admin_term in path_lower for admin_term in ['admin', 'manage', 'console']):
            tags.append("Admin")

        return tags if tags else ["General"]

    def _extract_resource_name(self, path: str) -> str:
        """Extract resource name from path for description generation"""
        parts = path.strip('/').split('/')
        skip_parts = ['api', 'rest', 'v1', 'v2', 'v3', 'v4', 'v5']

        for part in parts:
            if part.lower() not in skip_parts and not part.startswith('{'):
                return part.replace('_', ' ').replace('-', ' ')

        return "resource"

    def _infer_action(self, method: str, path: str) -> str:
        """Infer the action being performed based on method and path"""
        actions = {
            'GET': 'Retrieve' if '{' in path else 'List',
            'POST': 'Create',
            'PUT': 'Update',
            'PATCH': 'Partially update',
            'DELETE': 'Delete',
            'HEAD': 'Check existence of',
            'OPTIONS': 'Get options for'
        }

        return actions.get(method, 'Operate on')

    def _requires_authentication(self, endpoint: APIEndpoint) -> bool:
        """Determine if an endpoint requires authentication"""
        # Check if we used auth headers for this endpoint
        if self.auth_headers:
            return True

        # Check if endpoint returned 401 without auth
        if endpoint.status_code == 401:
            return True

        # Check if path suggests authentication is needed
        protected_patterns = ['admin', 'manage', 'profile', 'account', 'dashboard']
        return any(pattern in endpoint.path.lower() for pattern in protected_patterns)

    def _get_security_requirements(self, endpoint: APIEndpoint) -> List[Dict]:
        """Get security requirements for a specific endpoint"""
        security = []

        # Check what auth methods we detected for this API
        if hasattr(self, 'authenticated') and self.authenticated:
            if self.auth_token and 'Bearer' in self.auth_token:
                security.append({"BearerAuth": []})
            elif any('api' in h.lower() and 'key' in h.lower() for h in self.session.headers):
                security.append({"ApiKeyAuth": []})

        return security if security else [{}]

    def _get_status_description(self, status_code: int) -> str:
        """Get human-readable description for HTTP status codes"""
        descriptions = {
            200: "Success - Request completed successfully",
            201: "Created - Resource created successfully",
            202: "Accepted - Request accepted for processing",
            204: "No Content - Request successful, no content returned",
            400: "Bad Request - Invalid input parameters",
            401: "Unauthorized - Authentication required",
            403: "Forbidden - Insufficient permissions",
            404: "Not Found - Resource not found",
            405: "Method Not Allowed - HTTP method not supported",
            500: "Internal Server Error - Server error occurred"
        }

        return descriptions.get(status_code, f"HTTP {status_code}")

    def _extract_path_parameters(self, path: str, endpoints: List[APIEndpoint]) -> List[Dict]:
        """Extract path parameters from a path and endpoints"""
        parameters = []

        # Find path parameters in the path itself
        path_params = re.findall(r'\{([^}]+)\}', path)

        for param in path_params:
            param_obj = {
                "name": param,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": f"Path parameter {param}"
            }

            # Try to infer the type based on the parameter name
            if 'id' in param.lower():
                param_obj["schema"] = {"type": "integer", "format": "int64"}
                param_obj["description"] = f"Unique identifier for {param.replace('_id', '').replace('Id', '')}"

            parameters.append(param_obj)

        return parameters

    def _generate_schema_name(self, path: str, method: str) -> str:
        """Generate a schema name based on path and method"""
        # Extract resource name from path
        parts = path.strip('/').split('/')
        skip_parts = ['api', 'rest', 'v1', 'v2', 'v3', 'v4', 'v5']

        resource_parts = []
        for part in parts:
            if part.lower() not in skip_parts and not part.startswith('{'):
                resource_parts.append(part)

        if resource_parts:
            resource = ''.join(
                word.capitalize() for word in resource_parts[-1].replace('_', ' ').replace('-', ' ').split())

            # Add method-specific suffix
            if method == 'GET' and '{' not in path:
                return f"{resource}List"
            elif method == 'GET':
                return f"{resource}Detail"
            elif method == 'POST':
                return f"{resource}Create"
            elif method == 'PUT':
                return f"{resource}Update"
            else:
                return resource
        else:
            return f"{method.capitalize()}Response"

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a name for use in OpenAPI identifiers"""
        # Remove special characters and replace with underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        # Remove leading/trailing underscores and collapse multiple underscores
        sanitized = re.sub(r'_+', '_', sanitized).strip('_')
        # Ensure it doesn't start with a number
        if sanitized and sanitized[0].isdigit():
            sanitized = f"path_{sanitized}"
        return sanitized or "unnamed"

    def _get_performance_summary(self, analysis: APIAnalysis) -> Dict:
        """Get performance summary for metadata"""
        response_times = [e.response_time for e in analysis.discovered_endpoints if e.response_time > 0]

        if response_times:
            return {
                "average_response_time": sum(response_times) / len(response_times),
                "min_response_time": min(response_times),
                "max_response_time": max(response_times),
                "total_endpoints_tested": len(response_times)
            }
        else:
            return {
                "average_response_time": 0,
                "min_response_time": 0,
                "max_response_time": 0,
                "total_endpoints_tested": 0
            }

    def generate_postman_collection(self, analysis: APIAnalysis, output_file: str):
        """Generate Postman collection from analysis"""
        collection = {
            "info": {
                "name": f"API Collection - {urlparse(self.base_url).netloc}",
                "description": f"Auto-generated from API scanning of {self.base_url}",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "variable": [
                {
                    "key": "baseUrl",
                    "value": self.base_url,
                    "type": "string"
                }
            ],
            "item": []
        }

        # Group endpoints by path
        grouped_endpoints = defaultdict(list)
        for endpoint in analysis.discovered_endpoints:
            grouped_endpoints[endpoint.path].append(endpoint)

        for path, endpoints in grouped_endpoints.items():
            folder = {
                "name": path or "Root",
                "item": []
            }

            for endpoint in endpoints:
                if endpoint.status_code > 0:  # Only include successful discoveries
                    request = {
                        "name": f"{endpoint.method} {endpoint.path}",
                        "request": {
                            "method": endpoint.method,
                            "header": [
                                {"key": "Content-Type", "value": "application/json"}
                            ],
                            "url": {
                                "raw": f"{{{{baseUrl}}}}{endpoint.path}",
                                "host": ["{{baseUrl}}"],
                                "path": endpoint.path.split('/')[1:] if endpoint.path.startswith(
                                    '/') else endpoint.path.split('/')
                            }
                        }
                    }

                    # Add body for POST/PUT/PATCH
                    if endpoint.method in ['POST', 'PUT', 'PATCH']:
                        request["request"]["body"] = {
                            "mode": "raw",
                            "raw": json.dumps(self._generate_test_payload(endpoint.path), indent=2)
                        }

                    folder["item"].append(request)

            if folder["item"]:
                collection["item"].append(folder)

        with open(output_file, 'w') as f:
            json.dump(collection, f, indent=2)

        logger.info(f"Postman collection saved to {output_file}")

    def generate_openapi_spec(self, analysis: APIAnalysis, output_file: str):
        """Generate OpenAPI specification from analysis"""
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": f"API Specification - {urlparse(self.base_url).netloc}",
                "description": f"Auto-generated from API scanning of {self.base_url}",
                "version": "1.0.0"
            },
            "servers": [
                {"url": self.base_url}
            ],
            "paths": {}
        }

        # Group endpoints by path
        grouped_endpoints = defaultdict(list)
        for endpoint in analysis.discovered_endpoints:
            if endpoint.status_code > 0:
                grouped_endpoints[endpoint.path].append(endpoint)

        for path, endpoints in grouped_endpoints.items():
            path_spec = {}

            for endpoint in endpoints:
                method_spec = {
                    "summary": f"{endpoint.method} {endpoint.path}",
                    "responses": {
                        str(endpoint.status_code): {
                            "description": f"Response for {endpoint.method} {endpoint.path}"
                        }
                    }
                }

                # Add schema if available
                if endpoint.schema:
                    method_spec["responses"][str(endpoint.status_code)]["content"] = {
                        "application/json": {
                            "schema": endpoint.schema
                        }
                    }

                # Add parameters
                parameters = []
                for param in endpoint.parameters.get('path_parameters', []):
                    parameters.append({
                        "name": param,
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    })

                for param in endpoint.parameters.get('query_parameters', []):
                    parameters.append({
                        "name": param,
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"}
                    })

                if parameters:
                    method_spec["parameters"] = parameters

                path_spec[endpoint.method.lower()] = method_spec

            if path_spec:
                spec["paths"][path] = path_spec

        with open(output_file, 'w') as f:
            yaml.dump(spec, f, default_flow_style=False)

        logger.info(f"OpenAPI specification saved to {output_file}")

    def generate_report(self, analysis: APIAnalysis, output_file: str):
        """Generate comprehensive HTML report"""
        html_report = f'''<!DOCTYPE html>
<html>
<head>
    <title>API Analysis Report - {urlparse(self.base_url).netloc}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; }}
        .endpoint {{ background-color: #f9f9f9; padding: 10px; margin: 5px 0; border-left: 4px solid #007cba; }}
        .security-finding {{ background-color: #f8d7da; padding: 10px; border-left: 4px solid #dc3545; margin: 5px 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .stat-box {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>API Analysis Report</h1>
        <p><strong>Base URL:</strong> {analysis.base_url}</p>
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Endpoints:</strong> {len(analysis.discovered_endpoints)}</p>
    </div>

    <div class="section">
        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <h3>{len(analysis.discovered_endpoints)}</h3>
                <p>Total Endpoints</p>
            </div>
            <div class="stat-box">
                <h3>{len([e for e in analysis.discovered_endpoints if e.status_code < 400])}</h3>
                <p>Successful Responses</p>
            </div>
            <div class="stat-box">
                <h3>{len([e for e in analysis.discovered_endpoints if e.status_code >= 400])}</h3>
                <p>Error Responses</p>
            </div>
        </div>
    </div>
</body>
</html>'''

        with open(output_file, 'w') as f:
            f.write(html_report)

        logger.info(f"HTML report saved to {output_file}")

    def export_csv(self, analysis: APIAnalysis, output_file: str):
        """Export endpoint data to CSV"""
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = [
                'path', 'method', 'status_code', 'response_time', 'content_type', 'error'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for endpoint in analysis.discovered_endpoints:
                row = {
                    'path': endpoint.path,
                    'method': endpoint.method,
                    'status_code': endpoint.status_code,
                    'response_time': endpoint.response_time,
                    'content_type': endpoint.content_type,
                    'error': endpoint.error or ''
                }
                writer.writerow(row)

        logger.info(f"CSV export saved to {output_file}")


def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Universal API Parameter Scanner')
    parser.add_argument('base_url', help='Base URL of the API to scan')
    parser.add_argument('--paths', nargs='*', help='Additional paths to test')
    parser.add_argument('--output-dir', default='./api_scan_results', help='Output directory for results')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum concurrent workers')
    parser.add_argument('--rate-limit', type=float, default=0.1, help='Delay between requests in seconds')
    parser.add_argument('--deep-scan', action='store_true', help='Enable deep scanning (more comprehensive but slower)')
    parser.add_argument('--verify-ssl', action='store_true', default=True, help='Verify SSL certificates')
    parser.add_argument('--no-ssl-verify', dest='verify_ssl', action='store_false', help='Skip SSL verification')
    parser.add_argument('--format', choices=['all', 'json', 'html', 'csv', 'postman', 'openapi', 'swagger-builder'],
                        default='all', help='Output format(s)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')

    # Swagger builder specific options
    parser.add_argument('--swagger-output', help='Filename for Swagger builder optimized output (YAML format)')

    # Basic authentication options
    parser.add_argument('--auth-header', help='Authorization header (e.g., "Bearer token123")')
    parser.add_argument('--api-key-header', help='API key header name and value (e.g., "X-API-Key:key123")')

    # Advanced authentication options
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument('--auth-method',
                            choices=['auto', 'basic', 'bearer', 'api_key', 'oauth2', 'jwt', 'session', 'custom'],
                            default='auto', help='Authentication method (default: auto-detect)')
    auth_group.add_argument('--username', help='Username for authentication')
    auth_group.add_argument('--password', help='Password for authentication')
    auth_group.add_argument('--token', help='Bearer token or JWT token')
    auth_group.add_argument('--api-key', help='API key value')
    auth_group.add_argument('--api-key-name', default='X-API-Key', help='API key header name (default: X-API-Key)')
    auth_group.add_argument('--client-id', help='OAuth2 client ID')
    auth_group.add_argument('--client-secret', help='OAuth2 client secret')

    # Endpoint configuration
    endpoint_group = parser.add_argument_group('Authentication Endpoints')
    endpoint_group.add_argument('--login-endpoint', help='Custom login endpoint (e.g., /api/auth/login)')
    endpoint_group.add_argument('--token-endpoint', help='Custom token endpoint (e.g., /api/auth/token)')
    endpoint_group.add_argument('--refresh-endpoint', help='Custom refresh endpoint (e.g., /api/auth/refresh)')
    endpoint_group.add_argument('--logout-endpoint', help='Custom logout endpoint (e.g., /api/auth/logout)')

    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--credentials-file', help='JSON file containing credentials')
    advanced_group.add_argument('--session-file', help='File to save/load session data')
    advanced_group.add_argument('--custom-auth-url', help='Custom authentication URL')
    advanced_group.add_argument('--custom-auth-method', default='POST', help='Custom auth HTTP method')
    advanced_group.add_argument('--custom-auth-payload', help='Custom auth payload (JSON string)')
    advanced_group.add_argument('--custom-auth-headers', help='Custom auth headers (JSON string)')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build credentials dictionary
    credentials = {}
    auth_headers = {}

    # Handle basic auth options
    if args.auth_header:
        auth_headers['Authorization'] = args.auth_header
    if args.api_key_header:
        key, value = args.api_key_header.split(':', 1)
        auth_headers[key] = value

    # Handle advanced auth options
    if args.username:
        credentials['username'] = args.username
    if args.password:
        credentials['password'] = args.password
    if args.token:
        credentials['token'] = args.token
    if args.api_key:
        credentials['api_key'] = args.api_key
        credentials['api_key_header'] = args.api_key_name
    if args.client_id:
        credentials['client_id'] = args.client_id
    if args.client_secret:
        credentials['client_secret'] = args.client_secret

    # Handle custom authentication
    if args.custom_auth_url:
        custom_auth = {
            'url': args.custom_auth_url,
            'method': args.custom_auth_method
        }

        if args.custom_auth_payload:
            try:
                custom_auth['payload'] = json.loads(args.custom_auth_payload)
            except json.JSONDecodeError:
                logger.error("Invalid JSON in custom auth payload")
                return

        if args.custom_auth_headers:
            try:
                custom_auth['headers'] = json.loads(args.custom_auth_headers)
            except json.JSONDecodeError:
                logger.error("Invalid JSON in custom auth headers")
                return

        credentials['custom_auth'] = custom_auth

    # Load credentials from file if specified
    if args.credentials_file:
        try:
            with open(args.credentials_file, 'r') as f:
                file_credentials = json.load(f)
                credentials.update(file_credentials)
        except Exception as e:
            logger.error(f"Could not load credentials file: {e}")
            return

    # Create output directory
    import os
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize scanner with credentials
    scanner = UniversalAPIScanner(
        base_url=args.base_url,
        timeout=args.timeout,
        max_workers=args.max_workers,
        rate_limit_delay=args.rate_limit,
        auth_headers=auth_headers,
        verify_ssl=args.verify_ssl,
        deep_scan=args.deep_scan,
        credentials=credentials,
        auth_method=args.auth_method,
        login_endpoint=args.login_endpoint,
        token_endpoint=args.token_endpoint,
        refresh_endpoint=args.refresh_endpoint,
        logout_endpoint=args.logout_endpoint
    )

    try:
        # Perform scan
        logger.info(f"Starting comprehensive scan of {args.base_url}")
        if credentials:
            logger.info(f"Using authentication method: {args.auth_method}")

        analysis = scanner.scan_comprehensive(args.paths)

        # Save session data if requested
        if args.session_file and scanner.authenticated:
            session_data = {
                'auth_token': scanner.auth_token,
                'refresh_token': scanner.refresh_token,
                'session_cookies': scanner.session_cookies,
                'csrf_token': scanner.csrf_token,
                'authenticated': scanner.authenticated
            }

            try:
                with open(args.session_file, 'w') as f:
                    json.dump(session_data, f, indent=2)
                logger.info(f"Session data saved to {args.session_file}")
            except Exception as e:
                logger.warning(f"Could not save session data: {e}")

        # Generate outputs
        base_name = urlparse(args.base_url).netloc.replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if args.format == 'all' or args.format == 'json':
            json_file = os.path.join(args.output_dir, f"{base_name}_{timestamp}.json")
            with open(json_file, 'w') as f:
                json.dump(asdict(analysis), f, indent=2, default=str)
            logger.info(f"JSON analysis saved to {json_file}")

        if args.format == 'all' or args.format == 'html':
            html_file = os.path.join(args.output_dir, f"{base_name}_{timestamp}.html")
            scanner.generate_report(analysis, html_file)

        if args.format == 'all' or args.format == 'csv':
            csv_file = os.path.join(args.output_dir, f"{base_name}_{timestamp}.csv")
            scanner.export_csv(analysis, csv_file)

        if args.format == 'all' or args.format == 'postman':
            postman_file = os.path.join(args.output_dir, f"{base_name}_{timestamp}_postman.json")
            scanner.generate_postman_collection(analysis, postman_file)

        if args.format == 'all' or args.format == 'openapi':
            openapi_file = os.path.join(args.output_dir, f"{base_name}_{timestamp}_openapi.yaml")
            scanner.generate_openapi_spec(analysis, openapi_file)

        # Generate Swagger builder format
        if args.format == 'all' or args.format == 'swagger-builder' or args.swagger_output:
            swagger_file = args.swagger_output or os.path.join(args.output_dir,
                                                               f"{base_name}_{timestamp}_swagger_builder.yaml")
            swagger_data = scanner.generate_swagger_builder_format(analysis, swagger_file)

            # Print summary of what was generated
            print(f"\n🎯 SWAGGER BUILDER OUTPUT GENERATED")
            print(f"📄 Main file: {swagger_file}")
            print(f"📄 JSON file: {swagger_file.replace('.yaml', '.json').replace('.yml', '.json')}")
            print(f"📊 Paths discovered: {len(swagger_data['paths'])}")
            print(f"📋 Schemas generated: {len(swagger_data['components']['schemas'])}")
            print(f"🏷️  Tags created: {len(swagger_data['tags'])}")
            print(f"🔐 Security schemes: {len(swagger_data['components']['securitySchemes'])}")

        # Print summary
        print(f"\n{'=' * 60}")
        print(f"API SCAN COMPLETE")
        print(f"{'=' * 60}")
        print(f"Base URL: {analysis.base_url}")
        print(f"Authentication: {'✅ Success' if scanner.authenticated else '❌ Not authenticated'}")
        print(f"Endpoints discovered: {len(analysis.discovered_endpoints)}")
        print(f"Successful responses: {len([e for e in analysis.discovered_endpoints if e.status_code < 400])}")
        print(f"Error responses: {len([e for e in analysis.discovered_endpoints if e.status_code >= 400])}")
        print(
            f"Authentication methods: {', '.join(analysis.authentication_methods) if analysis.authentication_methods else 'None detected'}")
        print(f"Security findings: {len(analysis.security_findings)}")
        print(f"Results saved to: {args.output_dir}")
        print(f"{'=' * 60}")

        if analysis.security_findings:
            print("\nSECURITY FINDINGS:")
            for finding in analysis.security_findings:
                print(f"  ⚠️  {finding}")

        if scanner.authenticated:
            print(f"\n🔐 AUTHENTICATION SUCCESS:")
            print(f"  Method: {args.auth_method}")
            print(f"  Token: {'Yes' if scanner.auth_token else 'No'}")
            print(f"  Session: {'Yes' if scanner.session_cookies else 'No'}")
            print(f"  Refresh: {'Yes' if scanner.refresh_token else 'No'}")

        # Show Swagger-specific info if generated
        if args.format == 'all' or args.format == 'swagger-builder' or args.swagger_output:
            print(f"\n📚 SWAGGER DOCUMENTATION READY:")
            print(f"  Import {swagger_file} into Swagger Editor")
            print(f"  Use for generating client SDKs")
            print(f"  Base for comprehensive API documentation")
            print(f"  Ready for OpenAPI 3.0 tooling")

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise


if __name__ == "__main__":
    main()
