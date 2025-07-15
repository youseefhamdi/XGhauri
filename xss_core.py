#!/usr/bin/env python3
"""
XGhauri Core Module - Main XSS exploitation logic
"""

import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

from .analyzer import ResponseAnalyzer
from .burp_importer import BurpImporter
from .trainer import XSSTrainer
from .browser_engine import BrowserEngine
from .utils.payload_generator import PayloadGenerator
from .utils.report_generator import ReportGenerator


@dataclass
class XSSResult:
    """Data class for XSS vulnerability results"""
    url: str
    parameter: str
    payload: str
    xss_type: str  # Reflected, Stored, DOM
    severity: str
    evidence: str
    screenshot_path: Optional[str] = None
    bypass_technique: Optional[str] = None


class XSSCore:
    """Main XSS exploitation engine"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Initialize components
        self.analyzer = ResponseAnalyzer()
        self.burp_importer = BurpImporter()
        self.trainer = XSSTrainer()
        self.browser_engine = BrowserEngine()
        self.payload_generator = PayloadGenerator()
        self.report_generator = ReportGenerator()
        
        # Results storage
        self.results: List[XSSResult] = []
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'XGhauri/1.0 (Advanced XSS Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def load_payloads(self, payload_file: str) -> List[str]:
        """Load XSS payloads from file"""
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(payloads)} payloads from {payload_file}")
            return payloads
        except Exception as e:
            self.logger.error(f"Failed to load payloads: {e}")
            return []
    
    def extract_parameters(self, request_data: Dict) -> Dict[str, str]:
        """Extract parameters from request data"""
        parameters = {}
        
        # Extract GET parameters
        if 'url' in request_data:
            parsed_url = urlparse(request_data['url'])
            get_params = parse_qs(parsed_url.query)
            for key, values in get_params.items():
                parameters[key] = values[0] if values else ''
        
        # Extract POST parameters
        if 'data' in request_data:
            if isinstance(request_data['data'], dict):
                parameters.update(request_data['data'])
            elif isinstance(request_data['data'], str):
                # Parse form data
                post_params = parse_qs(request_data['data'])
                for key, values in post_params.items():
                    parameters[key] = values[0] if values else ''
        
        return parameters
    
    def inject_payload(self, request_data: Dict, parameter: str, payload: str) -> Dict:
        """Inject payload into specific parameter"""
        modified_request = request_data.copy()
        
        # Handle URL parameters
        if parameter in self.extract_parameters(request_data):
            if 'url' in modified_request:
                parsed_url = urlparse(modified_request['url'])
                params = parse_qs(parsed_url.query)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                modified_request['url'] = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        # Handle POST data
        if 'data' in modified_request and isinstance(modified_request['data'], dict):
            if parameter in modified_request['data']:
                modified_request['data'][parameter] = payload
        
        return modified_request
    
    async def test_xss_payload(self, request_data: Dict, parameter: str, payload: str) -> Optional[XSSResult]:
        """Test a single XSS payload"""
        try:
            # Inject payload
            modified_request = self.inject_payload(request_data, parameter, payload)
            
            # Send request
            response = self.session.request(
                method=modified_request.get('method', 'GET'),
                url=modified_request['url'],
                data=modified_request.get('data'),
                headers=modified_request.get('headers', {}),
                timeout=self.config.get('timeout', 10)
            )
            
            # Analyze response
            is_vulnerable, xss_type, evidence = self.analyzer.analyze_response(
                response, payload, parameter
            )
            
            if is_vulnerable:
                # Verify with browser automation
                browser_confirmed = await self.browser_engine.verify_xss(
                    modified_request['url'], payload
                )
                
                if browser_confirmed:
                    # Capture screenshot
                    screenshot_path = await self.browser_engine.capture_screenshot(
                        modified_request['url'], payload
                    )
                    
                    result = XSSResult(
                        url=modified_request['url'],
                        parameter=parameter,
                        payload=payload,
                        xss_type=xss_type,
                        severity=self.analyzer.assess_severity(xss_type, payload),
                        evidence=evidence,
                        screenshot_path=screenshot_path
                    )
                    
                    # Train AI model with successful result
                    await self.trainer.learn_from_result(result, response)
                    
                    return result
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error testing payload {payload}: {e}")
            return None
    
    async def scan_target(self, request_data: Dict) -> List[XSSResult]:
        """Scan target for XSS vulnerabilities"""
        results = []
        parameters = self.extract_parameters(request_data)
        
        self.logger.info(f"Scanning {len(parameters)} parameters for XSS")
        
        for parameter in parameters:
            # Get smart payloads from AI trainer
            smart_payloads = await self.trainer.generate_smart_payloads(
                request_data, parameter
            )
            
            # Load baseline payloads
            baseline_payloads = self.load_payloads('payloads/payloads.txt')
            
            # Combine and prioritize payloads
            all_payloads = smart_payloads + baseline_payloads
            
            for payload in all_payloads[:self.config.get('max_payloads', 100)]:
                result = await self.test_xss_payload(request_data, parameter, payload)
                if result:
                    results.append(result)
                    self.logger.info(f"XSS found in parameter '{parameter}' with payload: {payload}")
                    
                    # Stop testing this parameter if vulnerability found
                    if self.config.get('stop_on_first_vuln', False):
                        break
        
        return results
    
    async def run_scan(self, target_input: str) -> None:
        """Main scanning function"""
        if target_input.endswith('.xml'):
            # Process Burp Suite XML export
            requests_data = self.burp_importer.parse_burp_xml(target_input)
        else:
            # Process single URL
            requests_data = [{
                'url': target_input,
                'method': 'GET',
                'headers': {},
                'data': {}
            }]
        
        self.logger.info(f"Processing {len(requests_data)} requests")
        
        for request_data in requests_data:
            results = await self.scan_target(request_data)
            self.results.extend(results)
        
        # Generate reports
        if self.results:
            self.report_generator.generate_json_report(self.results)
            self.report_generator.generate_html_report(self.results)
            self.logger.info(f"Scan complete. Found {len(self.results)} vulnerabilities")
        else:
            self.logger.info("No XSS vulnerabilities found")
