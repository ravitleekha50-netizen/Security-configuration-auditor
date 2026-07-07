import socket
import threading
from typing import List, Dict, Any

class PortScanner:
    def __init__(self, target: str, ports: List[int] = None):
        self.target = target
        if ports is None:
            self.ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
        else:
            self.ports = ports
        self.results = []
        self.lock = threading.Lock()

    def scan_port(self, port: int):
        status = "Closed"
        service = "Unknown"
        
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            pass

        try:
            ip = socket.gethostbyname(self.target)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            res = sock.connect_ex((ip, port))
            if res == 0:
                status = "Open"
            sock.close()
        except Exception:
            pass

        with self.lock:
            self.results.append({
                "port": port,
                "service": service,
                "status": status
            })

    def run_scan(self) -> List[Dict[str, Any]]:
        threads = []
        for port in self.ports:
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.results.sort(key=lambda x: x["port"])
        return self.results
