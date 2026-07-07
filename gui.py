import tkinter as tk
from tkinter import ttk, messagebox
import threading
import webbrowser
from auditor.url_scanner import HeaderAuditor
from auditor.ssl_checker import SSLChecker
from auditor.xss_detector import XSSDetector
from auditor.sql_injection_tester import SQLInjectionTester
from reports.report_generator import ReportGenerator

BG_MAIN = "#0f172a"
BG_CARD = "#1e293b"
ACCENT_BLUE = "#3b82f6"
ACCENT_GREEN = "#10b981"
ACCENT_RED = "#ef4444"
ACCENT_YELLOW = "#f59e0b"
TEXT_PRIMARY = "#f8fafc"
TEXT_MUTED = "#94a3b8"

class SecurityAuditorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Passive Security Configuration Auditor")
        self.root.geometry("820x760")
        self.root.configure(bg=BG_MAIN)
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.style.configure(".", background=BG_MAIN, foreground=TEXT_PRIMARY)
        self.style.configure("TLabel", background=BG_MAIN, foreground=TEXT_PRIMARY, font=("Segoe UI", 10))
        self.style.configure("Card.TFrame", background=BG_CARD, relief="flat")
        self.style.configure("CardLabel.TLabel", background=BG_CARD, foreground=TEXT_PRIMARY, font=("Segoe UI", 10))
        self.style.configure("MutedLabel.TLabel", background=BG_CARD, foreground=TEXT_MUTED, font=("Segoe UI", 9))
        
        self.style.configure(
            "Primary.TButton", 
            background=ACCENT_BLUE, 
            foreground=TEXT_PRIMARY, 
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
            focuscolor=ACCENT_BLUE
        )
        self.style.map("Primary.TButton", background=[("active", "#2563eb"), ("disabled", "#475569")])
        
        self.style.configure(
            "Secondary.TButton", 
            background="#334155", 
            foreground=TEXT_PRIMARY, 
            font=("Segoe UI", 9, "bold"),
            borderwidth=0
        )
        self.style.map("Secondary.TButton", background=[("active", "#475569"), ("disabled", "#1e293b")])

        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground=ACCENT_BLUE)
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 9), foreground=TEXT_MUTED)

        self.create_widgets()

    def create_widgets(self):
        header_frame = tk.Frame(self.root, bg=BG_MAIN)
        header_frame.pack(pady=(25, 15), fill="x", padx=25)
        
        title_label = ttk.Label(header_frame, text="Security Configuration Auditor", style="Header.TLabel")
        title_label.pack(anchor="w")
        
        sub_label = ttk.Label(header_frame, text="Passive configuration and SSL/TLS diagnostic engine • Educational Audit Tool", style="SubHeader.TLabel")
        sub_label.pack(anchor="w", pady=(2, 0))

        control_card = ttk.Frame(self.root, style="Card.TFrame", padding=15)
        control_card.pack(padx=25, fill="x")
        
        url_label = ttk.Label(control_card, text="Target Domain / URL:", style="CardLabel.TLabel")
        url_label.pack(anchor="w", pady=(0, 5))
        
        input_row = tk.Frame(control_card, bg=BG_CARD)
        input_row.pack(fill="x")
        
        self.url_entry = tk.Entry(
            input_row, 
            font=("Segoe UI", 11), 
            bg="#0f172a", 
            fg=TEXT_PRIMARY, 
            insertbackground="white", 
            relief="flat", 
            bd=8
        )
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.url_entry.insert(0, "example.com")
        self.url_entry.bind("<Return>", lambda e: self.start_audit())
        
        self.scan_btn = ttk.Button(input_row, text="Launch Audit", style="Primary.TButton", command=self.start_audit)
        self.scan_btn.pack(side="right", padx=(12, 0))

        self.summary_frame = tk.Frame(self.root, bg=BG_MAIN)
        self.summary_frame.pack(padx=25, pady=15, fill="x")
        
        self.header_card = ttk.Frame(self.summary_frame, style="Card.TFrame", padding=12)
        self.header_card.pack(side="left", fill="both", expand=True, padx=(0, 6))
        
        self.h_status_title = ttk.Label(self.header_card, text="Security Headers Status", style="MutedLabel.TLabel")
        self.h_status_title.pack(anchor="w")
        
        self.h_status_val = tk.Label(self.header_card, text="Pending Scan", font=("Segoe UI", 12, "bold"), fg=TEXT_MUTED, bg=BG_CARD)
        self.h_status_val.pack(anchor="w", pady=(4, 0))

        self.ssl_card = ttk.Frame(self.summary_frame, style="Card.TFrame", padding=12)
        self.ssl_card.pack(side="left", fill="both", expand=True, padx=(6, 6))
        
        self.ssl_status_title = ttk.Label(self.ssl_card, text="SSL/TLS Validity", style="MutedLabel.TLabel")
        self.ssl_status_title.pack(anchor="w")
        
        self.ssl_status_val = tk.Label(self.ssl_card, text="Pending Scan", font=("Segoe UI", 12, "bold"), fg=TEXT_MUTED, bg=BG_CARD)
        self.ssl_status_val.pack(anchor="w", pady=(4, 0))

        self.appsec_card = ttk.Frame(self.summary_frame, style="Card.TFrame", padding=12)
        self.appsec_card.pack(side="left", fill="both", expand=True, padx=(6, 0))

        self.appsec_status_title = ttk.Label(self.appsec_card, text="XSS / SQLi Tests", style="MutedLabel.TLabel")
        self.appsec_status_title.pack(anchor="w")

        self.appsec_status_val = tk.Label(self.appsec_card, text="Pending Scan", font=("Segoe UI", 12, "bold"), fg=TEXT_MUTED, bg=BG_CARD)
        self.appsec_status_val.pack(anchor="w", pady=(4, 0))

        self.progress_bar = ttk.Progressbar(self.root, mode="indeterminate")

        console_label = ttk.Label(self.root, text="Diagnostic Log Output", font=("Segoe UI", 9, "bold"), foreground=TEXT_MUTED)
        console_label.pack(anchor="w", padx=25, pady=(5, 3))
        
        output_card = ttk.Frame(self.root, style="Card.TFrame", padding=1)
        output_card.pack(padx=25, fill="both", expand=True)
        
        self.output_text = tk.Text(
            output_card, 
            wrap="word", 
            font=("Consolas", 10), 
            bg="#0b0f19", 
            fg=TEXT_PRIMARY, 
            insertbackground="white",
            relief="flat",
            bd=10
        )
        self.output_text.pack(side="left", fill="both", expand=True)
        
        self.output_text.tag_config("info", foreground=ACCENT_BLUE)
        self.output_text.tag_config("success", foreground=ACCENT_GREEN)
        self.output_text.tag_config("warning", foreground=ACCENT_YELLOW)
        self.output_text.tag_config("error", foreground=ACCENT_RED)
        
        scrollbar = ttk.Scrollbar(output_card, command=self.output_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.output_text.config(yscrollcommand=scrollbar.set)

        footer_frame = tk.Frame(self.root, bg=BG_MAIN)
        footer_frame.pack(pady=20, padx=25, fill="x")
        
        self.disclaimer_lbl = ttk.Label(
            footer_frame, 
            text="🔒 Passive scan mode sends standard packets only. No exploit attempts are performed.", 
            font=("Segoe UI", 8),
            foreground=TEXT_MUTED
        )
        self.disclaimer_lbl.pack(side="left")
        
        self.view_html_btn = ttk.Button(
            footer_frame, 
            text="Open HTML Report", 
            style="Secondary.TButton", 
            command=self.open_html_report, 
            state="disabled"
        )
        self.view_html_btn.pack(side="right")

    def log(self, message: str, tag: str = None):
        self.output_text.insert(tk.END, message, tag)
        self.output_text.see(tk.END)
        self.root.update_idletasks()

    def start_audit(self):
        target = self.url_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please specify a target domain or URL.")
            return
            
        self.scan_btn.config(state="disabled")
        self.progress_bar.pack(pady=(0, 10), padx=25, fill="x")
        self.progress_bar.start(10)
        
        self.output_text.delete("1.0", tk.END)
        
        self.h_status_val.config(text="Scanning...", fg=TEXT_MUTED)
        self.ssl_status_val.config(text="Scanning...", fg=TEXT_MUTED)
        self.appsec_status_val.config(text="Scanning...", fg=TEXT_MUTED)
        
        self.log("[*] Initializing audit procedures...\n", "info")
        self.log(f"[*] Target selected: {target}\n", "info")
        
        thread = threading.Thread(target=self.run_audit_thread, args=(target,))
        thread.daemon = True
        thread.start()

    def run_audit_thread(self, target):
        try:
            self.log("[*] Fetching HTTP security configurations...\n", "info")
            auditor = HeaderAuditor(target)
            header_results = auditor.audit_headers()
            
            self.log("[*] Establishing secure socket for TLS evaluation...\n", "info")
            ssl_checker = SSLChecker(target)
            ssl_results = ssl_checker.check_certificate()

            self.log("[*] Running reflected XSS checks...\n", "info")
            xss_detector = XSSDetector(target)
            xss_results = xss_detector.run_scan()

            self.log("[*] Running SQL injection checks...\n", "info")
            sql_tester = SQLInjectionTester(target)
            sql_results = sql_tester.run_scan()
            
            self.log("[*] Compiling text and HTML reports...\n", "info")
            
            generator = ReportGenerator(header_results, ssl_results, xss_results, sql_results)
            text_report = generator.generate_text_report()
            html_report = generator.generate_html_report()
            
            with open("audit_report.txt", "w", encoding="utf-8") as f:
                f.write(text_report)
            with open("audit_report.html", "w", encoding="utf-8") as f:
                f.write(html_report)
                
            self.root.after(0, lambda: self.finish_audit(header_results, ssl_results, xss_results, sql_results, text_report))
            
        except Exception as e:
            self.root.after(0, lambda: self.handle_error(str(e)))

    def finish_audit(self, header_res, ssl_res, xss_res, sql_res, report_text):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.scan_btn.config(state="normal")
        self.view_html_btn.config(state="normal")
        
        if header_res.get("error"):
            self.h_status_val.config(text="Error Check", fg=ACCENT_RED)
            self.log(f"[!] Headers check failed: {header_res['error']}\n", "error")
        else:
            present_headers = sum(1 for h in header_res["security_headers"].values() if h["present"])
            total_headers = len(header_res["security_headers"])
            
            if present_headers == total_headers:
                self.h_status_val.config(text="Fully Protected", fg=ACCENT_GREEN)
            elif present_headers > 0:
                self.h_status_val.config(text=f"{present_headers}/{total_headers} Configured", fg=ACCENT_YELLOW)
            else:
                self.h_status_val.config(text="No Headers Active", fg=ACCENT_RED)

        if ssl_res.get("error"):
            self.ssl_status_val.config(text="No HTTPS / Expired", fg=ACCENT_RED)
            self.log(f"[!] SSL/TLS verification error: {ssl_res['error']}\n", "error")
        else:
            if ssl_res["valid"]:
                days = ssl_res.get("days_remaining", 0)
                self.ssl_status_val.config(text=f"Active ({days}d left)", fg=ACCENT_GREEN)
            else:
                self.ssl_status_val.config(text="Invalid Certificate", fg=ACCENT_RED)

        xss_findings = len(xss_res.get("findings", [])) if xss_res else 0
        sql_findings = len(sql_res.get("findings", [])) if sql_res else 0
        if xss_res.get("error") or sql_res.get("error"):
            self.appsec_status_val.config(text="Check Error", fg=ACCENT_YELLOW)
        elif xss_findings or sql_findings:
            self.appsec_status_val.config(text=f"{xss_findings + sql_findings} Finding(s)", fg=ACCENT_RED)
        else:
            self.appsec_status_val.config(text="No Findings", fg=ACCENT_GREEN)

        self.log("\n--- AUDIT COMPLETE ---\n\n", "success")
        self.output_text.insert(tk.END, report_text)
        self.log("\n[+] Diagnostic reports exported successfully to working directory.", "success")

    def handle_error(self, error_msg):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.scan_btn.config(state="normal")
        self.log(f"\n[!] Audit interrupted: {error_msg}\n", "error")
        
        self.h_status_val.config(text="Failed", fg=ACCENT_RED)
        self.ssl_status_val.config(text="Failed", fg=ACCENT_RED)
        self.appsec_status_val.config(text="Failed", fg=ACCENT_RED)
        messagebox.showerror("Audit Error", f"The diagnostic run encountered an issue:\n{error_msg}")

    def open_html_report(self):
        try:
            webbrowser.open("audit_report.html")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch web browser: {e}")

def start_gui():
    root = tk.Tk()
    app = SecurityAuditorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    start_gui()
