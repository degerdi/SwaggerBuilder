#!/usr/bin/env python3

"""
Clean Working Universal API Scanner - All Issues Fixed
"""

import requests
import json
import re
import time
import argparse
import csv
import os
import platform
import threading
import concurrent.futures
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from threading import Lock
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_scanner.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def safe_print(text):
    """Print text safely on Windows"""
    try:
        print(text)
    except UnicodeEncodeError:
        try:
            ascii_text = str(text).encode('ascii', errors='replace').decode('ascii')
            print(ascii_text)
        except:
            print("[Output encoding error]")
    except Exception:
        print("[Print error]")


@dataclass
class EndpointPattern:
    pattern: str
    category: str
    priority: int
    framework: str
    industry: str
    description: str


@dataclass
class APIEndpoint:
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
    discovered_at: str = None
    thread_id: str = None


class PatternManager:
    """Manages endpoint patterns from CSV file"""

    def __init__(self, csv_file: str = "endpoint_patterns.csv"):
        self.csv_file = csv_file
        self.patterns: List[EndpointPattern] = []
        self.categories = set()
        self.frameworks = set()
        self.industries = set()
        self.load_patterns()

    def load_patterns(self):
        """Load patterns from CSV file"""
        if not os.path.exists(self.csv_file):
            logger.warning(f"Pattern CSV file not found: {self.csv_file}")
            self._create_default_csv()

        try:
            with open(self.csv_file, 'r', encoding='utf-8') as f:
                csv_reader = csv.DictReader(f)
                for row in csv_reader:
                    if row.get('pattern', '').startswith('#'):
                        continue
                    try:
                        pattern = EndpointPattern(
                            pattern=row['pattern'].strip(),
                            category=row['category'].strip(),
                            priority=int(row.get('priority', 2)),
                            framework=row.get('framework', 'any').strip(),
                            industry=row.get('industry', 'any').strip(),
                            description=row.get('description', '').strip()
                        )
                        if pattern.pattern:
                            self.patterns.append(pattern)
                            self.categories.add(pattern.category)
                            self.frameworks.add(pattern.framework)
                            self.industries.add(pattern.industry)
                    except (ValueError, KeyError) as e:
                        logger.debug(f"Skipping invalid pattern row: {row} - {e}")
                        continue

            logger.info(f"Loaded {len(self.patterns)} patterns from {self.csv_file}")

        except Exception as e:
            logger.error(f"Error loading patterns from CSV: {e}")
            self._load_fallback_patterns()

    def _create_default_csv(self):
        """Create a default CSV file with basic patterns"""
        default_patterns = [
            ("/get", "testing", 1, "httpbin", "testing", "HTTPBin GET endpoint"),
            ("/post", "testing", 1, "httpbin", "testing", "HTTPBin POST endpoint"),
            ("/headers", "testing", 1, "httpbin", "testing", "HTTPBin headers"),
            ("/ip", "testing", 1, "httpbin", "testing", "HTTPBin IP"),
            ("/status/200", "testing", 1, "httpbin", "testing", "HTTPBin status 200"),
            ("/json", "testing", 1, "httpbin", "testing", "HTTPBin JSON"),
            ("/xml", "testing", 1, "httpbin", "testing", "HTTPBin XML"),
            ("/uuid", "testing", 1, "httpbin", "testing", "HTTPBin UUID"),
            ("/api", "core", 1, "any", "any", "Main API endpoint"),
            ("/api/v1", "core", 1, "any", "any", "API version 1"),
            ("/health", "health", 1, "any", "any", "Health check"),
            ("/status", "health", 1, "any", "any", "Status check"),
            ("/users", "users", 1, "any", "any", "Users endpoint"),
            ("/user", "users", 1, "any", "any", "User endpoint"),
        ]

        try:
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['pattern', 'category', 'priority', 'framework', 'industry', 'description'])
                for pattern_data in default_patterns:
                    writer.writerow(pattern_data)
            logger.info(f"Created default pattern file: {self.csv_file}")
        except Exception as e:
            logger.error(f"Could not create default CSV file: {e}")

    def _load_fallback_patterns(self):
        """Load basic fallback patterns"""
        fallback_patterns = [
            "/get", "/post", "/headers", "/ip", "/status/200", "/json", "/xml", "/uuid",
            "/api", "/api/v1", "/health", "/status", "/users", "/user"
        ]
        for pattern in fallback_patterns:
            self.patterns.append(EndpointPattern(
                pattern=pattern, category="core", priority=1, framework="any",
                industry="any", description=f"Fallback: {pattern}"
            ))

    def get_patterns(self, categories=None, frameworks=None, industries=None,
                     max_priority=None, limit=None) -> List[str]:
        """Get filtered patterns"""
        filtered_patterns = []

        for pattern in self.patterns:
            if categories and pattern.category not in categories:
                continue
            if frameworks and pattern.framework not in frameworks and pattern.framework != 'any':
                continue
            if industries and pattern.industry not in industries and pattern.industry != 'any':
                continue
            if max_priority and pattern.priority > max_priority:
                continue
            filtered_patterns.append(pattern)

        filtered_patterns.sort(key=lambda x: x.priority)
        pattern_strings = [p.pattern for p in filtered_patterns]

        if limit:
            pattern_strings = pattern_strings[:limit]

        return pattern_strings

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics"""
        return {
            'total_patterns': len(self.patterns),
            'categories': list(self.categories),
            'frameworks': list(self.frameworks),
            'industries': list(self.industries)
        }


class SimpleYAMLWriter:
    """Simplified YAML writer that works reliably"""

    def __init__(self, output_file: str, base_url: str):
        self.output_file = output_file
        self.base_url = base_url
        self.lock = Lock()
        self.stats = {
            'endpoints_discovered': 0,
            'schemas_generated': 0,
            'examples_created': 0,
            'last_updated': None
        }
        self.endpoints = []

        # Create initial file
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write("# API Scanner Results\n")
                f.write(f"# Target: {base_url}\n")
                f.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            logger.info(f"YAML writer initialized: {output_file}")
        except Exception as e:
            logger.error(f"Failed to initialize: {e}")

    def add_endpoint(self, endpoint):
        """Add endpoint safely"""
        try:
            with self.lock:
                self.endpoints.append({
                    'method': str(endpoint.method),
                    'path': str(endpoint.path),
                    'status': int(endpoint.status_code),
                    'time': round(float(endpoint.response_time), 3),
                    'content_type': str(endpoint.content_type or ''),
                    'thread': str(endpoint.thread_id or '')
                })
                self.stats['endpoints_discovered'] += 1
                self.stats['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Write immediately
            self._write_file()

            safe_print(f"[+] Added: {endpoint.method} {endpoint.path} (Status: {endpoint.status_code})")

        except Exception as e:
            logger.error(f"Error adding endpoint: {e}")
            with self.lock:
                self.stats['endpoints_discovered'] += 1

    def _write_file(self):
        """Write current data to file"""
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                # Write YAML header
                f.write("openapi: 3.0.3\n")
                f.write("info:\n")
                f.write(f"  title: API Documentation - {urlparse(self.base_url).netloc}\n")
                f.write(f"  description: Auto-discovered API for {self.base_url}\n")
                f.write("  version: 1.0.0\n")
                f.write("servers:\n")
                f.write(f"- url: {self.base_url}\n")
                f.write("  description: Discovered API Server\n")
                f.write("paths:\n")

                # Group endpoints by path
                paths_dict = {}
                for ep in self.endpoints:
                    if ep['path'] not in paths_dict:
                        paths_dict[ep['path']] = []
                    paths_dict[ep['path']].append(ep)

                # Write paths
                for path, endpoints in paths_dict.items():
                    f.write(f"  {path}:\n")
                    for ep in endpoints:
                        f.write(f"    {ep['method'].lower()}:\n")
                        f.write(f"      summary: {ep['method']} {ep['path']}\n")
                        f.write(f"      description: 'Discovered endpoint - Status: {ep['status']}'\n")
                        f.write(f"      responses:\n")
                        f.write(f"        '{ep['status']}':\n")
                        f.write(f"          description: HTTP {ep['status']}\n")
                        if ep['content_type']:
                            f.write(f"      x-content-type: '{ep['content_type']}'\n")
                        f.write(f"      x-discovery-info:\n")
                        f.write(f"        response_time: {ep['time']}\n")
                        f.write(f"        thread_id: '{ep['thread']}'\n")

                # Write components and stats
                f.write("components:\n")
                f.write("  schemas: {}\n")
                f.write("  examples: {}\n")
                f.write("x-discovery-stats:\n")
                f.write(f"  endpoints_discovered: {self.stats['endpoints_discovered']}\n")
                f.write(f"  schemas_generated: {self.stats['schemas_generated']}\n")
                f.write(f"  examples_created: {self.stats['examples_created']}\n")
                f.write(f"  last_updated: '{self.stats['last_updated']}'\n")

        except Exception as e:
            logger.error(f"Write error: {e}")

    def finalize(self):
        """Final write"""
        try:
            self._write_file()
            logger.info(f"Final write completed: {self.output_file}")
        except Exception as e:
            logger.error(f"Finalize error: {e}")

    def get_stats(self):
        """Get stats"""
        with self.lock:
            return self.stats.copy()


class UniversalAPIScanner:
    """Universal API Scanner - Clean Working Version"""

    def __init__(self, base_url: str, pattern_manager: PatternManager, **kwargs):
        self.base_url = base_url.rstrip('/')
        self.pattern_manager = pattern_manager
        self.session = requests.Session()

        # Configuration
        self.discovery_threads = kwargs.get('discovery_threads', 4)
        self.analysis_threads = kwargs.get('analysis_threads', 2)
        self.timeout = kwargs.get('timeout', 30)
        self.rate_limit_delay = kwargs.get('rate_limit_delay', 0.1)
        self.auth_headers = kwargs.get('auth_headers', {})

        # Pattern filtering
        self.categories = kwargs.get('categories', None)
        self.frameworks = kwargs.get('frameworks', None)
        self.industries = kwargs.get('industries', None)
        self.max_priority = kwargs.get('max_priority', None)
        self.pattern_limit = kwargs.get('pattern_limit', None)

        # Thread safety
        self.lock = threading.Lock()
        self.session_lock = threading.Lock()

        self._setup_session()
        logger.info(f"Scanner initialized for {self.base_url}")

    def _setup_session(self):
        """Configure session"""
        self.session.timeout = self.timeout

        headers = {
            'User-Agent': 'Universal-API-Scanner/2.1-Clean',
            'Accept': 'application/json, application/xml, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache'
        }
        headers.update(self.auth_headers)
        self.session.headers.update(headers)

        logger.info(f"Session configured for {self.base_url}")

    def _test_path_fast(self, path: str) -> bool:
        """Fast path testing"""
        try:
            url = urljoin(self.base_url, path)
            with self.session_lock:
                response = self.session.head(url, timeout=5, allow_redirects=False)

            success = response.status_code < 500 and response.status_code != 404
            if success:
                logger.debug(f"Found: {path} (Status: {response.status_code})")
            return success

        except Exception as e:
            logger.debug(f"Error testing {path}: {e}")
            return False

    def discover_endpoints_parallel(self, custom_paths: List[str] = None) -> Set[str]:
        """Parallel endpoint discovery"""
        logger.info(f"Starting discovery with {self.discovery_threads} threads")

        # Get patterns
        patterns = self.pattern_manager.get_patterns(
            categories=self.categories,
            frameworks=self.frameworks,
            industries=self.industries,
            max_priority=self.max_priority,
            limit=self.pattern_limit
        )

        if custom_paths:
            patterns.extend(custom_paths)

        patterns = list(set(patterns))
        logger.info(f"Testing {len(patterns)} patterns")

        discovered = set()
        completed_count = 0
        counter_lock = threading.Lock()

        def worker_function(pattern_batch):
            nonlocal completed_count
            local_discovered = set()

            for pattern in pattern_batch:
                try:
                    if self._test_path_fast(pattern):
                        local_discovered.add(pattern)
                        safe_print(f"[+] Found: {pattern}")

                    with counter_lock:
                        completed_count += 1
                        if completed_count % 10 == 0:
                            safe_print(f"Progress: {completed_count}/{len(patterns)} tested")

                    if self.rate_limit_delay > 0:
                        time.sleep(self.rate_limit_delay)

                except Exception as e:
                    logger.debug(f"Error testing {pattern}: {e}")
                    with counter_lock:
                        completed_count += 1

            return local_discovered

        # Split into batches
        batch_size = max(1, len(patterns) // self.discovery_threads)
        pattern_batches = [patterns[i:i + batch_size] for i in range(0, len(patterns), batch_size)]

        # Run in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.discovery_threads) as executor:
            future_to_batch = {executor.submit(worker_function, batch): batch for batch in pattern_batches}

            for future in concurrent.futures.as_completed(future_to_batch, timeout=120):
                try:
                    batch_results = future.result()
                    discovered.update(batch_results)
                except Exception as e:
                    logger.error(f"Worker batch failed: {e}")

        safe_print(f"\nDiscovery complete: {len(discovered)} endpoints found")
        logger.info(f"Discovery complete: {len(discovered)} endpoints found")

        # Manual fallback if none found
        if len(discovered) == 0:
            logger.warning("No endpoints found, trying manual test...")
            manual_patterns = ['/get', '/post', '/status/200', '/headers', '/ip', '/json']
            for pattern in manual_patterns:
                try:
                    url = urljoin(self.base_url, pattern)
                    response = self.session.get(url, timeout=10)
                    if response.status_code < 500:
                        discovered.add(pattern)
                        logger.info(f"Manual test found: {pattern}")
                except Exception as e:
                    logger.debug(f"Manual test failed for {pattern}: {e}")

        return discovered

    def analyze_endpoint_detailed(self, path: str) -> Optional[APIEndpoint]:
        """Analyze endpoint in detail"""
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']

        for method in methods:
            try:
                url = urljoin(self.base_url, path)
                start_time = time.time()

                with self.session_lock:
                    response = self.session.request(method, url, timeout=self.timeout)

                response_time = time.time() - start_time

                if response.status_code < 500:
                    try:
                        response_text = response.text if hasattr(response, 'text') else ""
                        if len(response_text) > 1000:
                            response_text = response_text[:1000]
                    except:
                        response_text = "<encoding error>"

                    endpoint = APIEndpoint(
                        path=path,
                        method=method,
                        parameters={},
                        headers=dict(response.request.headers),
                        status_code=response.status_code,
                        response_time=response_time,
                        response_body=response_text,
                        response_headers=dict(response.headers),
                        content_type=response.headers.get('Content-Type', ''),
                        discovered_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        thread_id=threading.current_thread().name
                    )

                    return endpoint

            except Exception as e:
                logger.debug(f"Error analyzing {method} {path}: {e}")
                continue

        return None

    def scan_with_realtime_output(self, output_file: str, custom_paths: List[str] = None) -> Dict:
        """Main scanning function"""
        logger.info("Starting scan with real-time output")

        # Initialize YAML writer
        try:
            yaml_writer = SimpleYAMLWriter(output_file, self.base_url)
            logger.info("YAML writer created successfully")
        except Exception as e:
            logger.error(f"Failed to create YAML writer: {e}")
            return {
                'endpoints_discovered': 0,
                'error': f"YAML writer failed: {e}"
            }

        try:
            # Phase 1: Discovery
            safe_print("Phase 1: Discovering endpoints...")
            discovered_paths = self.discover_endpoints_parallel(custom_paths)

            if not discovered_paths:
                logger.warning("No endpoints discovered")
                safe_print("WARNING: No endpoints discovered")
                yaml_writer.finalize()
                return yaml_writer.get_stats()

            # Phase 2: Analysis
            safe_print(f"\nPhase 2: Analyzing {len(discovered_paths)} endpoints...")

            def analyze_path_safe(path):
                try:
                    endpoint = self.analyze_endpoint_detailed(path)
                    if endpoint:
                        yaml_writer.add_endpoint(endpoint)
                        return 1
                    return 0
                except Exception as e:
                    logger.debug(f"Analysis error for {path}: {e}")
                    return 0

            # Run analysis
            analyzed_count = 0
            failed_count = 0

            max_workers = min(self.analysis_threads,
                              2) if platform.system().lower() == 'windows' else self.analysis_threads

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_path = {executor.submit(analyze_path_safe, path): path for path in discovered_paths}

                for future in concurrent.futures.as_completed(future_to_path, timeout=120):
                    try:
                        result = future.result()
                        if result > 0:
                            analyzed_count += result
                        else:
                            failed_count += 1

                        stats = yaml_writer.get_stats()
                        safe_print(f"\rProgress: {analyzed_count}/{len(discovered_paths)} analyzed, "
                                   f"{stats['endpoints_discovered']} in YAML")

                    except Exception as e:
                        failed_count += 1
                        logger.debug(f"Analysis future failed: {e}")

            # Final write
            yaml_writer.finalize()
            final_stats = yaml_writer.get_stats()

            # Summary
            safe_print(f"\nScan Summary:")
            safe_print(f"  [+] Analyzed: {analyzed_count}")
            safe_print(f"  [!] Failed: {failed_count}")
            safe_print(f"  [=] Total in YAML: {final_stats['endpoints_discovered']}")

            logger.info(f"Scan complete! Stats: {final_stats}")
            return final_stats

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            yaml_writer.finalize()
            raise
        finally:
            try:
                yaml_writer.finalize()
            except:
                pass


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Universal API Scanner - Clean Version')
    parser.add_argument('base_url', help='Base URL to scan')
    parser.add_argument('--paths', nargs='*', help='Additional paths')
    parser.add_argument('--output-dir', default='./api_scan_results', help='Output directory')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout')
    parser.add_argument('--rate-limit', type=float, default=0.1, help='Rate limit')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    # CSV Pattern options
    parser.add_argument('--pattern-file', default='endpoint_patterns.csv', help='Pattern CSV file')
    parser.add_argument('--categories', nargs='*', help='Categories to include')
    parser.add_argument('--frameworks', nargs='*', help='Frameworks to include')
    parser.add_argument('--max-priority', type=int, help='Max priority level')
    parser.add_argument('--pattern-limit', type=int, default=25, help='Pattern limit')

    # Threading options
    parser.add_argument('--discovery-threads', type=int, default=4, help='Discovery threads')
    parser.add_argument('--analysis-threads', type=int, default=2, help='Analysis threads')

    # Output options
    parser.add_argument('--swagger-output', default='api_scan_results.yaml', help='YAML output file')
    parser.add_argument('--auth-header', help='Authorization header')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize
    pattern_manager = PatternManager(args.pattern_file)

    auth_headers = {}
    if args.auth_header:
        auth_headers['Authorization'] = args.auth_header

    os.makedirs(args.output_dir, exist_ok=True)

    scanner = UniversalAPIScanner(
        base_url=args.base_url,
        pattern_manager=pattern_manager,
        timeout=args.timeout,
        rate_limit_delay=args.rate_limit,
        auth_headers=auth_headers,
        discovery_threads=args.discovery_threads,
        analysis_threads=args.analysis_threads,
        categories=args.categories,
        frameworks=args.frameworks,
        max_priority=args.max_priority,
        pattern_limit=args.pattern_limit
    )

    try:
        safe_print("Clean Universal API Scanner v2.1")
        safe_print(f"Target: {scanner.base_url}")
        safe_print(f"Threads: {args.discovery_threads} discovery, {args.analysis_threads} analysis")
        safe_print(f"Pattern limit: {args.pattern_limit}")
        safe_print("")

        # Run scan
        stats = scanner.scan_with_realtime_output(args.swagger_output, args.paths)

        # Results
        safe_print(f"\n[SUCCESS] Scan completed!")
        safe_print(f"YAML file: {args.swagger_output}")
        safe_print(f"Stats: {stats}")

        if os.path.exists(args.swagger_output):
            file_size = os.path.getsize(args.swagger_output)
            safe_print(f"File size: {file_size:,} bytes")

    except KeyboardInterrupt:
        safe_print("\n[STOPPED] Scan interrupted")
    except Exception as e:
        safe_print(f"\n[ERROR] Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()