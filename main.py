#!/usr/bin/env python3
"""
XGhauri - AI-Assisted XSS Exploitation Tool
Main entry point and CLI interface

Usage:
    python main.py --url https://example.com --burp-xml burp_export.xml --ai-mode
    python main.py --help
"""

import asyncio
import argparse
import sys
from pathlib import Path
from typing import List, Optional
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import core modules
from xghauri.xss_core import XSSCore
from xghauri.analyzer import ResponseAnalyzer
from xghauri.burp_importer import BurpImporter
from xghauri.trainer import XSSTrainer
from xghauri.browser_engine import BrowserEngine
from xghauri.utils.config import Config
from xghauri.utils.payload_generator import PayloadGenerator
from xghauri.utils.report_generator import ReportGenerator


class XGhauri:
    """Main XGhauri application class"""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize XGhauri with configuration"""
        self.config = Config(config_path)
        self.core = XSSCore(self.config)
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.analyzer = ResponseAnalyzer()
        self.burp_importer = BurpImporter()
        self.trainer = XSSTrainer()
        self.browser_engine = BrowserEngine()
        self.payload_generator = PayloadGenerator()
        self.report_generator = ReportGenerator()

        # Results storage
        self.results = []

        self.logger.info("XGhauri initialized successfully")

    async def scan_url(self, url: str, parameters: Optional[dict] = None) -> List[dict]:
        """Scan a single URL for XSS vulnerabilities"""
        self.logger.info(f"Starting XSS scan for URL: {url}")

        try:
            # Create request data structure
            request_data = {
                'url': url,
                'method': 'GET',
                'headers': {'User-Agent': 'XGhauri/1.0'},
                'data': parameters or {}
            }

            # Run the scan
            results = await self.core.scan_target(request_data)
            self.results.extend(results)

            self.logger.info(f"Scan completed. Found {len(results)} vulnerabilities")
            return results

        except Exception as e:
            self.logger.error(f"Error scanning URL {url}: {e}")
            return []

    async def scan_burp_export(self, burp_xml_path: str) -> List[dict]:
        """Scan requests from Burp Suite XML export"""
        self.logger.info(f"Processing Burp Suite XML export: {burp_xml_path}")

        try:
            # Parse Burp XML
            requests_data = self.burp_importer.parse_burp_xml(burp_xml_path)

            self.logger.info(f"Loaded {len(requests_data)} requests from Burp export")

            # Scan each request
            all_results = []
            for request_data in requests_data:
                results = await self.core.scan_target(request_data)
                all_results.extend(results)

            self.results.extend(all_results)

            self.logger.info(f"Burp scan completed. Found {len(all_results)} vulnerabilities")
            return all_results

        except Exception as e:
            self.logger.error(f"Error processing Burp export: {e}")
            return []

    async def run_ai_enhanced_scan(self, target: str, ai_mode: bool = True) -> List[dict]:
        """Run an AI-enhanced XSS scan"""
        self.logger.info(f"Starting AI-enhanced scan for: {target}")

        try:
            # Determine if target is URL or Burp export
            if target.endswith('.xml'):
                results = await self.scan_burp_export(target)
            else:
                results = await self.scan_url(target)

            # If AI mode is enabled, enhance results with AI analysis
            if ai_mode and results:
                self.logger.info("Running AI enhancement on results...")
                enhanced_results = await self.trainer.enhance_results(results)
                results = enhanced_results

            return results

        except Exception as e:
            self.logger.error(f"Error in AI-enhanced scan: {e}")
            return []

    def generate_reports(self, output_format: str = 'html') -> None:
        """Generate vulnerability reports"""
        if not self.results:
            self.logger.warning("No results to generate reports from")
            return

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            if output_format.lower() == 'html':
                report_path = f"xghauri_report_{timestamp}.html"
                self.report_generator.generate_html_report(self.results, report_path)
            elif output_format.lower() == 'json':
                report_path = f"xghauri_report_{timestamp}.json"
                self.report_generator.generate_json_report(self.results, report_path)
            else:
                # Generate both formats
                html_path = f"xghauri_report_{timestamp}.html"
                json_path = f"xghauri_report_{timestamp}.json"
                self.report_generator.generate_html_report(self.results, html_path)
                self.report_generator.generate_json_report(self.results, json_path)

            self.logger.info(f"Reports generated successfully")

        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")

    def print_summary(self) -> None:
        """Print scan summary"""
        if not self.results:
            print("\n🔍 No XSS vulnerabilities found.")
            return

        print(f"\n🚨 Found {len(self.results)} XSS vulnerabilities:")
        print("=" * 60)

        for i, result in enumerate(self.results, 1):
            print(f"\n{i}. {result.xss_type} XSS - {result.severity}")
            print(f"   URL: {result.url}")
            print(f"   Parameter: {result.parameter}")
            print(f"   Payload: {result.payload}")
            if result.bypass_technique:
                print(f"   Bypass: {result.bypass_technique}")
            if result.screenshot_path:
                print(f"   Screenshot: {result.screenshot_path}")

        print("=" * 60)
        print(f"\n📊 Summary by severity:")
        severity_counts = {}
        for result in self.results:
            severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1

        for severity, count in sorted(severity_counts.items()):
            print(f"   {severity}: {count}")


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser"""
    epilog_text = """
Examples:
  python main.py --url https://example.com/search?q=test
  python main.py --burp-xml burp_export.xml --ai-mode
  python main.py --url https://example.com --parameters "{'name': 'test'}"
  python main.py --url https://example.com --output-format json
    """

    parser = argparse.ArgumentParser(
        description='XGhauri - AI-Assisted XSS Exploitation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog_text
    )

    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--url', '-u', 
                             help='Target URL to scan')
    target_group.add_argument('--burp-xml', '-b',
                             help='Path to Burp Suite XML export file')

    # Scan options
    parser.add_argument('--parameters', '-p',
                       help='Parameters to test (JSON format)')
    parser.add_argument('--ai-mode', '-a', action='store_true',
                       help='Enable AI-enhanced scanning')
    parser.add_argument('--max-payloads', '-m', type=int, default=100,
                       help='Maximum number of payloads to test per parameter')
    parser.add_argument('--threads', '-t', type=int, default=5,
                       help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds')

    # Output options
    parser.add_argument('--output-format', '-o', 
                       choices=['html', 'json', 'both'], default='html',
                       help='Output report format')
    parser.add_argument('--silent', '-s', action='store_true',
                       help='Silent mode (minimal output)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    # Configuration
    parser.add_argument('--config', '-c',
                       help='Path to configuration file')

    return parser


async def main():
    """Main application entry point"""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.silent:
        logging.getLogger().setLevel(logging.WARNING)

    # Banner
    if not args.silent:
        print("""
██╗  ██╗ ██████╗ ██╗  ██╗ █████╗ ██╗   ██╗██████╗ ██╗
╚██╗██╔╝██╔════╝ ██║  ██║██╔══██╗██║   ██║██╔══██╗██║
 ╚███╔╝ ██║  ███╗███████║███████║██║   ██║██████╔╝██║
 ██╔██╗ ██║   ██║██╔══██║██╔══██║██║   ██║██╔══██╗██║
██╔╝ ██╗╚██████╔╝██║  ██║██║  ██║╚██████╔╝██║  ██║██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝

AI-Assisted XSS Exploitation Tool v1.0
Created for ethical hacking and security research
        """)

    try:
        # Initialize XGhauri
        xghauri = XGhauri(args.config)

        # Determine target
        if args.url:
            target = args.url
            # Parse parameters if provided
            parameters = None
            if args.parameters:
                import json
                parameters = json.loads(args.parameters)
        else:
            target = args.burp_xml
            parameters = None

        # Run scan
        results = await xghauri.run_ai_enhanced_scan(target, args.ai_mode)

        # Generate reports
        xghauri.generate_reports(args.output_format)

        # Print summary
        if not args.silent:
            xghauri.print_summary()

        # Exit with appropriate code
        sys.exit(0 if not results else 1)

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Run the main application
    asyncio.run(main())
