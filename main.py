#!/usr/bin/env python3
"""
XGhauri - Advanced AI-Powered XSS Exploitation Tool
Author: AI Security Research Team
Version: 1.0.0
Date: 2025

An intelligent XSS exploitation tool that integrates with Burp Suite Pro
and uses AI/ML techniques for adaptive payload generation and WAF bypass.
"""

import argparse
import sys
import os
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.xss_core import XSSCore
from core.scanner import XSSScanner
from utils.logger import setup_logger
from utils.banner import display_banner
from config.settings import Settings

def main():
    """Main entry point for XGhauri"""

    # Display banner
    display_banner()

    # Setup argument parser
    parser = argparse.ArgumentParser(
        description='XGhauri - Advanced AI-Powered XSS Exploitation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -u https://example.com/search?q=test
  %(prog)s -u https://example.com/search?q=test --burp-proxy
  %(prog)s -u https://example.com/search?q=test --ai-mode
  %(prog)s --burp-import requests.xml
  %(prog)s --crawl https://example.com --depth 2
  %(prog)s --train payload_responses.json
        '''
    )

    # Target options
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument('-u', '--url', help='Target URL to scan')
    target_group.add_argument('-f', '--file', help='File containing URLs to scan')
    target_group.add_argument('--crawl', help='Crawl website starting from this URL')
    target_group.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')

    # Burp Suite integration
    burp_group = parser.add_argument_group('Burp Suite Integration')
    burp_group.add_argument('--burp-import', help='Import requests from Burp Suite XML/JSON')
    burp_group.add_argument('--burp-proxy', action='store_true', help='Use Burp Suite as proxy')
    burp_group.add_argument('--burp-api-key', help='Burp Suite API key')
    burp_group.add_argument('--burp-host', default='127.0.0.1', help='Burp Suite host')
    burp_group.add_argument('--burp-port', type=int, default=8080, help='Burp Suite port')

    # AI/ML options
    ai_group = parser.add_argument_group('AI/ML Options')
    ai_group.add_argument('--ai-mode', action='store_true', help='Enable AI-powered payload generation')
    ai_group.add_argument('--train', help='Train AI model with payload response data')
    ai_group.add_argument('--model-path', help='Path to custom AI model')
    ai_group.add_argument('--mutation-rate', type=float, default=0.1, help='Payload mutation rate')

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--payloads', help='Custom payload file')
    scan_group.add_argument('--threads', type=int, default=10, help='Number of threads')
    scan_group.add_argument('--delay', type=float, default=0.1, help='Delay between requests')
    scan_group.add_argument('--timeout', type=int, default=30, help='Request timeout')
    scan_group.add_argument('--user-agent', help='Custom User-Agent')
    scan_group.add_argument('--headers', action='append', help='Custom headers (key:value)')
    scan_group.add_argument('--cookies', help='Custom cookies')

    # Detection options
    detection_group = parser.add_argument_group('Detection Options')
    detection_group.add_argument('--verify-browser', action='store_true', help='Verify XSS with browser automation')
    detection_group.add_argument('--browser', default='chrome', choices=['chrome', 'firefox', 'safari'], help='Browser for verification')
    detection_group.add_argument('--headless', action='store_true', help='Run browser in headless mode')
    detection_group.add_argument('--screenshot', action='store_true', help='Take screenshots of successful XSS')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', help='Output file for results')
    output_group.add_argument('--format', choices=['json', 'xml', 'html', 'csv'], default='json', help='Output format')
    output_group.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    output_group.add_argument('--silent', '-s', action='store_true', help='Silent mode')

    # Parse arguments
    args = parser.parse_args()

    # Validate arguments
    if not any([args.url, args.file, args.crawl, args.burp_import, args.train]):
        parser.error("Must specify target URL, file, crawl target, Burp import, or training data")

    # Setup logger
    logger = setup_logger(verbose=args.verbose, silent=args.silent)

    # Initialize settings
    settings = Settings()

    # Update settings with CLI arguments
    settings.update_from_args(args)

    try:
        # Training mode
        if args.train:
            from ai.trainer import XSSTrainer
            trainer = XSSTrainer(settings)
            trainer.train_from_file(args.train)
            return

        # Initialize scanner
        scanner = XSSScanner(settings)

        # Import from Burp Suite
        if args.burp_import:
            scanner.import_from_burp(args.burp_import)

        # Crawl mode
        elif args.crawl:
            scanner.crawl_and_scan(args.crawl, depth=args.depth)

        # File mode
        elif args.file:
            scanner.scan_from_file(args.file)

        # Single URL mode
        elif args.url:
            scanner.scan_single_url(args.url)

        # Generate final report
        scanner.generate_report()

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
