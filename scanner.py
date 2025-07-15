#!/usr/bin/env python3
"""
XSS Scanner - Orchestrates the scanning process
"""

import os
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin

from core.xss_core import XSSCore, XSSVulnerability
from utils.logger import get_logger
from utils.crawler import WebCrawler
from utils.report_generator import ReportGenerator
from burp_integration.burp_importer import BurpImporter

class XSSScanner:
    """Main XSS scanner class"""

    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.xss_core = XSSCore(settings)
        self.crawler = WebCrawler(settings)
        self.report_generator = ReportGenerator(settings)
        self.burp_importer = BurpImporter(settings)

        # Results storage
        self.all_vulnerabilities: List[XSSVulnerability] = []
        self.scan_queue = queue.Queue()
        self.completed_scans = 0
        self.total_scans = 0

        # Thread safety
        self.lock = threading.Lock()

    def scan_single_url(self, url: str) -> List[XSSVulnerability]:
        """Scan a single URL for XSS vulnerabilities"""
        self.logger.info(f"Starting single URL scan: {url}")

        start_time = time.time()

        try:
            vulnerabilities = self.xss_core.scan_url(url)

            with self.lock:
                self.all_vulnerabilities.extend(vulnerabilities)

            self.logger.info(f"Scan completed in {time.time() - start_time:.2f}s")
            self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities")

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error scanning URL {url}: {e}")
            return []

    def scan_from_file(self, file_path: str) -> List[XSSVulnerability]:
        """Scan URLs from a file"""
        self.logger.info(f"Starting file-based scan: {file_path}")

        urls = []
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return []

        self.logger.info(f"Loaded {len(urls)} URLs from file")

        return self._scan_url_list(urls)

    def crawl_and_scan(self, start_url: str, depth: int = 2) -> List[XSSVulnerability]:
        """Crawl a website and scan discovered URLs"""
        self.logger.info(f"Starting crawl and scan: {start_url} (depth: {depth})")

        # Crawl the website
        discovered_urls = self.crawler.crawl(start_url, depth)

        self.logger.info(f"Crawling discovered {len(discovered_urls)} URLs")

        # Scan discovered URLs
        return self._scan_url_list(discovered_urls)

    def import_from_burp(self, burp_file: str) -> List[XSSVulnerability]:
        """Import requests from Burp Suite and scan them"""
        self.logger.info(f"Importing from Burp Suite: {burp_file}")

        requests_data = self.burp_importer.import_requests(burp_file)

        self.logger.info(f"Imported {len(requests_data)} requests from Burp Suite")

        return self._scan_burp_requests(requests_data)

    def _scan_url_list(self, urls: List[str]) -> List[XSSVulnerability]:
        """Scan a list of URLs using multithreading"""
        self.total_scans = len(urls)
        self.completed_scans = 0

        all_vulnerabilities = []

        with ThreadPoolExecutor(max_workers=self.settings.threads) as executor:
            # Submit all scanning tasks
            future_to_url = {
                executor.submit(self.xss_core.scan_url, url): url 
                for url in urls
            }

            # Process completed tasks
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)

                    with self.lock:
                        self.completed_scans += 1
                        self.all_vulnerabilities.extend(vulnerabilities)

                    self.logger.info(f"Completed {self.completed_scans}/{self.total_scans}: {url}")

                except Exception as e:
                    self.logger.error(f"Error scanning {url}: {e}")
                    with self.lock:
                        self.completed_scans += 1

        return all_vulnerabilities

    def _scan_burp_requests(self, requests_data: List[Dict]) -> List[XSSVulnerability]:
        """Scan imported Burp Suite requests"""
        self.total_scans = len(requests_data)
        self.completed_scans = 0

        all_vulnerabilities = []

        with ThreadPoolExecutor(max_workers=self.settings.threads) as executor:
            # Submit all scanning tasks
            future_to_request = {
                executor.submit(self._scan_burp_request, request_data): request_data
                for request_data in requests_data
            }

            # Process completed tasks
            for future in as_completed(future_to_request):
                request_data = future_to_request[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)

                    with self.lock:
                        self.completed_scans += 1
                        self.all_vulnerabilities.extend(vulnerabilities)

                    self.logger.info(f"Completed {self.completed_scans}/{self.total_scans}: {request_data['url']}")

                except Exception as e:
                    self.logger.error(f"Error scanning request: {e}")
                    with self.lock:
                        self.completed_scans += 1

        return all_vulnerabilities

    def _scan_burp_request(self, request_data: Dict) -> List[XSSVulnerability]:
        """Scan a single Burp Suite request"""
        return self.xss_core.scan_url(
            url=request_data['url'],
            method=request_data['method'],
            data=request_data.get('data'),
            headers=request_data.get('headers')
        )

    def generate_report(self) -> str:
        """Generate a comprehensive scan report"""
        self.logger.info("Generating scan report...")

        with self.lock:
            vulnerabilities = self.all_vulnerabilities.copy()

        report_path = self.report_generator.generate_report(vulnerabilities)

        self.logger.info(f"Report generated: {report_path}")
        return report_path

    def get_scan_progress(self) -> Dict:
        """Get current scan progress"""
        with self.lock:
            return {
                'completed': self.completed_scans,
                'total': self.total_scans,
                'percentage': (self.completed_scans / self.total_scans * 100) if self.total_scans > 0 else 0,
                'vulnerabilities_found': len(self.all_vulnerabilities)
            }

    def get_vulnerabilities_summary(self) -> Dict:
        """Get a summary of found vulnerabilities"""
        with self.lock:
            vulnerabilities = self.all_vulnerabilities.copy()

        summary = {
            'total': len(vulnerabilities),
            'by_type': {},
            'by_severity': {},
            'by_confidence': {},
            'unique_parameters': set(),
            'unique_urls': set()
        }

        for vuln in vulnerabilities:
            # Count by type
            vuln_type = vuln.xss_type.value
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1

            # Count by severity
            severity = vuln.severity
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1

            # Count by confidence
            confidence_range = self._get_confidence_range(vuln.confidence)
            summary['by_confidence'][confidence_range] = summary['by_confidence'].get(confidence_range, 0) + 1

            # Track unique parameters and URLs
            summary['unique_parameters'].add(vuln.parameter)
            summary['unique_urls'].add(vuln.url)

        # Convert sets to counts
        summary['unique_parameters'] = len(summary['unique_parameters'])
        summary['unique_urls'] = len(summary['unique_urls'])

        return summary

    def _get_confidence_range(self, confidence: float) -> str:
        """Get confidence range string"""
        if confidence >= 0.9:
            return "high"
        elif confidence >= 0.7:
            return "medium"
        elif confidence >= 0.5:
            return "low"
        else:
            return "very_low"

    def stop_scan(self):
        """Stop the current scan"""
        self.logger.info("Stopping scan...")
        # Implementation depends on the specific threading model
        pass
