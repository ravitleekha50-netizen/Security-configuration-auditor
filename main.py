import argparse
import sys
from auditor.url_scanner import HeaderAuditor
from auditor.ssl_checker import SSLChecker
from auditor.xss_detector import XSSDetector
from auditor.sql_injection_tester import SQLInjectionTester
from reports.report_generator import ReportGenerator
from utils.logger import setup_logger
from gui import start_gui

DISCLAIMER = """
======================================================================
                         EDUCATIONAL USE ONLY
This utility performs passive configuration auditing on public systems.
Always ensure you have authorization to query target infrastructure.
======================================================================
"""

def main():
    if len(sys.argv) == 1:
        start_gui()
        return

    print(DISCLAIMER)
    logger = setup_logger()
    
    parser = argparse.ArgumentParser(description="Passive Security Configuration Auditor")
    parser.add_argument("target", help="The target URL or domain to audit (e.g., example.com)")
    args = parser.parse_args()

    logger.info(f"Initiating passive audit of: {args.target}")

    logger.info("Inspecting HTTP security response headers...")
    auditor = HeaderAuditor(args.target)
    header_results = auditor.audit_headers()

    logger.info("Checking SSL/TLS configuration...")
    ssl_checker = SSLChecker(args.target)
    ssl_results = ssl_checker.check_certificate()

    logger.info("Testing for reflected XSS indicators...")
    xss_detector = XSSDetector(args.target)
    xss_results = xss_detector.run_scan()

    logger.info("Testing for SQL injection indicators...")
    sql_tester = SQLInjectionTester(args.target)
    sql_results = sql_tester.run_scan()

    logger.info("Formatting security configuration report...")
    generator = ReportGenerator(header_results, ssl_results, xss_results, sql_results)
    text_report = generator.generate_text_report()
    html_report = generator.generate_html_report()

    print(text_report)

    txt_filename = "audit_report.txt"
    html_filename = "audit_report.html"
    try:
        with open(txt_filename, "w", encoding="utf-8") as f:
            f.write(text_report)
        logger.info(f"Text report successfully saved to: {txt_filename}")
        
        with open(html_filename, "w", encoding="utf-8") as f:
            f.write(html_report)
        logger.info(f"HTML report successfully saved to: {html_filename}")
        
    except IOError as e:
        logger.error(f"Failed to write report to file: {e}")

if __name__ == "__main__":
    main()
