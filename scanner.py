import os, argparse, json
from datetime import datetime
from colorama import Fore, Style, init
from modules.port_scanner import PortScanner
from modules.service_detect import banner_grab
from modules.vuln_check import analyze
from config.settings import DEFAULT_NETWORK, DEFAULT_PORTS, SCAN_ARGS, REPORT_DIR

init(autoreset=True)

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def html_report(results, outfile):
    ensure_dir(os.path.dirname(outfile))
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for host in results:
        proto = host["protocols"].get("tcp", {})
        for port, info in proto.items():
            rows.append(f"<tr><td>{host['target']}</td><td>{port}/tcp</td><td>{info.get('state')}</td>"
                        f"<td>{info.get('name') or ''}</td>"
                        f"<td>{(info.get('product') or '') + ' ' + (info.get('version') or '')}</td>"
                        f"<td>{info.get('extrainfo') or ''}</td></tr>")

    findings_rows = []
    for host in results:
        for f in host.get("findings", []):
            findings_rows.append(f"<tr><td>{host['target']}</td><td>{f['severity']}</td>"
                                 f"<td>{f['issue']}</td><td>{f['evidence']}</td>"
                                 f"<td>{f['recommendation']}</td></tr>")

    html = f"""<!doctype html><html><head>
    <meta charset="utf-8"><title>Network Scan Report</title></head><body>
    <h1>Network Scan Report</h1>
    <p><b>Generated:</b> {ts}</p>
    <h2>Open Services</h2>
    <table border="1">{''.join(rows) or '<tr><td>No services found</td></tr>'}</table>
    <h2>Findings</h2>
    <table border="1">{''.join(findings_rows) or '<tr><td>No findings</td></tr>'}</table>
    </body></html>"""

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)
    return outfile

def main():
    parser = argparse.ArgumentParser(description="Simple Network Security Scanner")
    parser.add_argument("-n","--network", default=DEFAULT_NETWORK, help="CIDR network")
    parser.add_argument("-t","--target", help="Single host")
    parser.add_argument("-p","--ports", default=DEFAULT_PORTS, help="Ports to scan")
    parser.add_argument("-a","--args", default=SCAN_ARGS, help="Extra nmap args")
    args = parser.parse_args()

    scanner = PortScanner()
    results = []

    if args.target:
        targets = [args.target]
    else:
        print(Fore.CYAN + f"[+] Discovering hosts in {args.network} ...")
        targets = scanner.discover_hosts(args.network)
        for h in targets: print("   -", h)

    print(Fore.CYAN + f"[+] Scanning {len(targets)} host(s)...")
    for host in targets:
        host_res = scanner.scan_host(host, args.ports, args.args)
        tcp = host_res["protocols"].get("tcp", {})
        for port in list(tcp.keys())[:5]:
            banner = banner_grab(host, port)
            if banner and not tcp[port].get("extrainfo"):
                tcp[port]["extrainfo"] = banner[:120]
        host_res["findings"] = analyze(host, host_res["protocols"])
        results.append(host_res)

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    outfile = os.path.join(REPORT_DIR, f"report-{timestamp}.html")
    path = html_report(results, outfile)

    print(Style.BRIGHT + Fore.GREEN + f"[✓] Report saved to {path}")
    with open(path.replace(".html", ".json"), "w") as jf:
        json.dump(results, jf, indent=2)

if __name__ == "__main__":
    main()
