#!/usr/bin/env python3
"""
XSS Core Engine - Main XSS exploitation logic
"""

import re
import time
import random
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

import requests
from bs4 import BeautifulSoup
import urllib3

from utils.logger import get_logger
from utils.http_client import HTTPClient
from modules.payload_generator import PayloadGenerator
from modules.response_analyzer import ResponseAnalyzer
from modules.context_analyzer import ContextAnalyzer
from modules.browser_verifier import BrowserVerifier

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSType(Enum):
    """XSS vulnerability types"""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"
    BLIND = "blind"

@dataclass
class XSSVulnerability:
    """Represents a discovered XSS vulnerability"""
    url: str
    parameter: str
    payload: str
    xss_type: XSSType
    severity: str
    context: str
    method: str
    evidence: str
    screenshot_path: Optional[str] = None
    timestamp: Optional[str] = None
    confidence: float = 0.0
    bypass_technique: Optional[str] = None

class XSSCore:
    """Main XSS exploitation engine"""

    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.http_client = HTTPClient(settings)
        self.payload_generator = PayloadGenerator(settings)
        self.response_analyzer = ResponseAnalyzer(settings)
        self.context_analyzer = ContextAnalyzer(settings)
        self.browser_verifier = BrowserVerifier(settings) if settings.verify_browser else None

        # Results storage
        self.vulnerabilities: List[XSSVulnerability] = []
        self.scan_stats = {
            'total_requests': 0,
            'total_payloads': 0,
            'vulnerabilities_found': 0,
            'false_positives': 0,
            'start_time': None,
            'end_time': None
        }

        # Thread safety
        self.lock = threading.Lock()

    def scan_url(self, url: str, method: str = 'GET', 
                 data: Optional[Dict] = None, 
                 headers: Optional[Dict] = None) -> List[XSSVulnerability]:
        """
        Scan a URL for XSS vulnerabilities

        Args:
            url: Target URL
            method: HTTP method
            data: POST data
            headers: HTTP headers

        Returns:
            List of discovered vulnerabilities
        """
        self.logger.info(f"Scanning URL: {url}")

        vulnerabilities = []

        try:
            # Parse URL and find injection points
            injection_points = self._find_injection_points(url, method, data)

            for injection_point in injection_points:
                self.logger.debug(f"Testing injection point: {injection_point['parameter']}")

                # Test for different XSS types
                vuln_list = self._test_injection_point(
                    injection_point, url, method, data, headers
                )
                vulnerabilities.extend(vuln_list)

        except Exception as e:
            self.logger.error(f"Error scanning URL {url}: {e}")

        return vulnerabilities

    def _find_injection_points(self, url: str, method: str, 
                              data: Optional[Dict] = None) -> List[Dict]:
        """Find potential injection points in the request"""
        injection_points = []

        # Parse URL parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Add URL parameters as injection points
        for param, values in params.items():
            for i, value in enumerate(values):
                injection_points.append({
                    'type': 'url',
                    'parameter': param,
                    'value': value,
                    'position': i,
                    'method': method
                })

        # Add POST data parameters
        if method.upper() == 'POST' and data:
            for param, value in data.items():
                injection_points.append({
                    'type': 'post',
                    'parameter': param,
                    'value': value,
                    'method': method
                })

        # Add headers that might be reflected
        reflected_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
        for header in reflected_headers:
            injection_points.append({
                'type': 'header',
                'parameter': header,
                'value': '',
                'method': method
            })

        return injection_points

    def _test_injection_point(self, injection_point: Dict, url: str, 
                             method: str, data: Optional[Dict] = None,
                             headers: Optional[Dict] = None) -> List[XSSVulnerability]:
        """Test a specific injection point for XSS"""
        vulnerabilities = []

        # Get context-specific payloads
        context_payloads = self._get_context_payloads(injection_point, url)

        for payload_info in context_payloads:
            payload = payload_info['payload']
            context = payload_info['context']

            try:
                # Create test request
                test_request = self._create_test_request(
                    url, method, data, headers, injection_point, payload
                )

                # Send request
                response = self.http_client.send_request(test_request)
                self.scan_stats['total_requests'] += 1

                # Analyze response
                analysis_result = self.response_analyzer.analyze_response(
                    response, payload, context
                )

                if analysis_result['is_vulnerable']:
                    vulnerability = XSSVulnerability(
                        url=url,
                        parameter=injection_point['parameter'],
                        payload=payload,
                        xss_type=XSSType(analysis_result['xss_type']),
                        severity=analysis_result['severity'],
                        context=context,
                        method=method,
                        evidence=analysis_result['evidence'],
                        confidence=analysis_result['confidence'],
                        bypass_technique=payload_info.get('bypass_technique'),
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                    )

                    # Browser verification if enabled
                    if self.browser_verifier and vulnerability.confidence > 0.7:
                        verification_result = self.browser_verifier.verify_xss(
                            test_request, payload
                        )
                        if verification_result['verified']:
                            vulnerability.screenshot_path = verification_result['screenshot']
                            vulnerability.confidence = min(1.0, vulnerability.confidence + 0.2)
                        else:
                            vulnerability.confidence *= 0.8

                    vulnerabilities.append(vulnerability)
                    self.scan_stats['vulnerabilities_found'] += 1

                    self.logger.info(f"XSS found: {vulnerability.parameter} - {vulnerability.payload}")

            except Exception as e:
                self.logger.error(f"Error testing payload {payload}: {e}")

            # Rate limiting
            if self.settings.delay > 0:
                time.sleep(self.settings.delay)

        return vulnerabilities

    def _get_context_payloads(self, injection_point: Dict, url: str) -> List[Dict]:
        """Get context-specific payloads for an injection point"""
        # First, determine the context by sending a probe
        context = self._determine_context(injection_point, url)

        # Generate payloads based on context
        if self.settings.ai_mode:
            payloads = self.payload_generator.generate_ai_payloads(context, injection_point)
        else:
            payloads = self.payload_generator.generate_context_payloads(context, injection_point)

        return payloads

    def _determine_context(self, injection_point: Dict, url: str) -> str:
        """Determine the injection context"""
        probe_payload = "xss_probe_" + str(random.randint(10000, 99999))

        try:
            test_request = self._create_test_request(
                url, injection_point['method'], None, None, injection_point, probe_payload
            )

            response = self.http_client.send_request(test_request)
            context = self.context_analyzer.analyze_context(response.text, probe_payload)

            self.logger.debug(f"Context determined: {context}")
            return context

        except Exception as e:
            self.logger.error(f"Error determining context: {e}")
            return "html"

    def _create_test_request(self, url: str, method: str, data: Optional[Dict],
                            headers: Optional[Dict], injection_point: Dict,
                            payload: str) -> Dict:
        """Create a test request with the payload"""
        test_request = {
            'url': url,
            'method': method,
            'headers': headers or {},
            'data': data.copy() if data else {},
            'params': {}
        }

        # Insert payload based on injection point type
        if injection_point['type'] == 'url':
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            params[injection_point['parameter']] = [payload]

            new_query = urlencode(params, doseq=True)
            test_request['url'] = urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                parsed_url.params, new_query, parsed_url.fragment
            ))

        elif injection_point['type'] == 'post':
            test_request['data'][injection_point['parameter']] = payload

        elif injection_point['type'] == 'header':
            test_request['headers'][injection_point['parameter']] = payload

        return test_request

    def get_scan_statistics(self) -> Dict:
        """Get scanning statistics"""
        with self.lock:
            return self.scan_stats.copy()

    def add_vulnerability(self, vulnerability: XSSVulnerability):
        """Add a vulnerability to the results"""
        with self.lock:
            self.vulnerabilities.append(vulnerability)

    def get_vulnerabilities(self) -> List[XSSVulnerability]:
        """Get all discovered vulnerabilities"""
        with self.lock:
            return self.vulnerabilities.copy()
