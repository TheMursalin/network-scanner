import nmap
from datetime import datetime

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def discover_hosts(self, network: str):
        self.nm.scan(hosts=network, arguments="-sn")
        hosts = [h for h in self.nm.all_hosts() if self.nm[h].state() in ("up", "unknown")]
        return hosts

    def scan_host(self, target: str, ports: str = "1-1024", args: str = "-sS -sV"):
        scan_result = {"target": target, "timestamp": datetime.utcnow().isoformat(), "protocols": {}}
        self.nm.scan(target, ports=ports, arguments=args)
        if target not in self.nm.all_hosts():
            return scan_result
        for proto in self.nm[target].all_protocols():
            scan_result["protocols"][proto] = {}
            for port in sorted(self.nm[target][proto].keys()):
                data = self.nm[target][proto][port]
                scan_result["protocols"][proto][port] = {
                    "state": data.get("state"),
                    "name": data.get("name"),
                    "product": data.get("product"),
                    "version": data.get("version"),
                    "extrainfo": data.get("extrainfo"),
                }
        return scan_result
