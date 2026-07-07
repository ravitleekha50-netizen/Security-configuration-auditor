import os
from flask import Flask, render_template, request, jsonify, Response
from auditor.url_scanner import HeaderAuditor
from auditor.ssl_checker import SSLChecker
from auditor.port_scanner import PortScanner
from auditor.xss_detector import XSSDetector
from auditor.sql_injection_tester import SQLInjectionTester
from reports.report_generator import ReportGenerator

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/audit', methods=['POST'])
def audit():
    target = request.json.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target is required'}), 400
        
    auditor = HeaderAuditor(target)
    header_res = auditor.audit_headers()
    
    ssl_checker = SSLChecker(target)
    ssl_res = ssl_checker.check_certificate()

    port_scanner = PortScanner(target)
    ports_res = port_scanner.run_scan()

    xss_detector = XSSDetector(target)
    xss_res = xss_detector.run_scan()

    sql_tester = SQLInjectionTester(target)
    sql_res = sql_tester.run_scan()
    
    return jsonify({
        'header': header_res,
        'ssl': ssl_res,
        'ports': ports_res,
        'xss': xss_res,
        'sql': sql_res,
        'heuristics': header_res.get('heuristics', {'suspicious': False, 'reasons': []})
    })

@app.route('/report/download', methods=['GET'])
def download_report():
    target = request.args.get('target', '').strip()
    format_type = request.args.get('format', 'html').strip()
    if not target:
        return "Target parameter is required", 400
        
    auditor = HeaderAuditor(target)
    header_res = auditor.audit_headers()
    
    ssl_checker = SSLChecker(target)
    ssl_res = ssl_checker.check_certificate()

    xss_detector = XSSDetector(target)
    xss_res = xss_detector.run_scan()

    sql_tester = SQLInjectionTester(target)
    sql_res = sql_tester.run_scan()

    generator = ReportGenerator(header_res, ssl_res, xss_res, sql_res)
    
    if format_type == 'text':
        content = generator.generate_text_report()
        mimetype = 'text/plain'
        filename = f"security_report_{target}.txt"
    else:
        content = generator.generate_html_report()
        mimetype = 'text/html'
        filename = f"security_report_{target}.html"
        
    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', debug=False, port=port)
