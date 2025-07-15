#!/usr/bin/env python3
"""
Burp Suite Integration Module
"""

import json
import xml.etree.ElementTree as ET
import base64
import requests
from typing import List, Dict, Optional
from urllib.parse import parse_qs, urlparse

from utils.logger import get_logger

class BurpImporter:
    """Import and parse Burp Suite requests"""
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.burp_api = BurpAPI(settings) if settings.burp_api_key else None
    
    def import_requests(self, file_path: str) -> List[Dict]:
        """Import requests from Burp Suite file"""
        self.logger.info(f"Importing requests from: {file_path}")
        
        if file_path.endswith('.xml'):
            return self._import_from_xml(file_path)
        elif file_path.endswith('.json'):
            return self._import_from_json(file_path)
        else:
            raise ValueError("Unsupported file format. Use XML or JSON.")
    
    def _import_from_xml(self, file_path: str) -> List[Dict]:
        """Import from Burp Suite XML export"""
        requests_data = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for item in root.findall('.//item'):
                request_data = self._parse_xml_item(item)
                if request_data:
                    requests_data.append(request_data)
            
            self.logger.info(f"Imported {len(requests_data)} requests from XML")
            return requests_data
            
        except Exception as e:
            self.logger.error(f"Error importing XML: {e}")
            return []
    
    def _parse_xml_item(self, item) -> Optional[Dict]:
        """Parse individual XML item"""
        try:
            # Extract basic request info
            url = item.find('url').text if item.find('url') is not None else None
            method = item.find('method').text if item.find('method') is not None else 'GET'
            
            # Extract request data
            request_element = item.find('request')
            if request_element is not None:
                request_data = base64.b64decode(request_element.text).decode('utf-8', errors='ignore')
                
                # Parse HTTP request
                parsed_request = self._parse_http_request(request_data)
                parsed_request['url'] = url
                parsed_request['method'] = method
                
                return parsed_request
                
        except Exception as e:
            self.logger.error(f"Error parsing XML item: {e}")
            return None
    
    def _parse_http_request(self, request_data: str) -> Dict:
        """Parse raw HTTP request"""
        lines = request_data.split('\n')
        
        # Parse request line
        request_line = lines[0].strip()
        method, path, version = request_line.split(' ', 2)
        
        # Parse headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Parse body
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        # Parse POST data if present
        post_data = {}
        if method.upper() == 'POST' and body:
            if headers.get('Content-Type', '').startswith('application/x-www-form-urlencoded'):
                post_data = dict(parse_qs(body))
            elif headers.get('Content-Type', '').startswith('application/json'):
                try:
                    post_data = json.loads(body)
                except json.JSONDecodeError:
                    post_data = {'raw': body}
        
        return {
            'method': method,
            'path': path,
            'headers': headers,
            'data': post_data,
            'body': body
        }

class BurpAPI:
    """Burp Suite REST API integration"""
    
    def __init__(self, settings):
        self.settings = settings
        self.base_url = f"http://{settings.burp_host}:{settings.burp_port}"
        self.api_key = settings.burp_api_key
        self.logger = get_logger()
    
    def get_proxy_history(self) -> List[Dict]:
        """Get proxy history from Burp Suite"""
        try:
            url = f"{self.base_url}/{self.api_key}/proxy/history"
            response = requests.get(url)
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Failed to get proxy history: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error accessing Burp API: {e}")
            return []
    
    def send_to_repeater(self, request_data: Dict) -> bool:
        """Send request to Burp Repeater"""
        try:
            url = f"{self.base_url}/{self.api_key}/repeater/send"
            response = requests.post(url, json=request_data)
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Error sending to Repeater: {e}")
            return False
