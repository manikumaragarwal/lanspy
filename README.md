# lanspy

ARP spoof + live packet sniffer for your own LAN. see every DNS query, HTTP request, and plaintext credential on the network in real time.

## setup

```bash
bash setup.sh
```

## run

```bash
# target all devices on LAN (auto-detects gateway)
sudo python3 lanspy.py

# target one specific device
sudo python3 lanspy.py -t 192.168.1.5

# just sniff DNS, no ARP spoofing (passive, stealthy)
sudo python3 lanspy.py --dns-only

# specify interface manually
sudo python3 lanspy.py -i en0
```

## what you see

| label | what it means |
|---|---|
| `DNS` | every domain name any device on the LAN looked up |
| `HTTP` | plaintext web requests — URL, method, host |
| `CRED` | POST bodies containing password-like fields |
| `COOK` | HTTP Set-Cookie headers (session tokens) |

## how it works

1. scans LAN for live hosts
2. ARP poisons them: tells each device "I am the router" and tells the router "I am that device"
3. traffic flows through this machine (IP forwarding enabled so it still reaches the destination)
4. scapy sniffs every packet and extracts DNS + HTTP layer info
5. on ctrl+c: restores ARP tables to correct state, disables IP forwarding

## limitations

- **HTTPS is encrypted** — you'll see the domain (via DNS) but not the content
- **certificate pinning** — apps that pin certs (most banking apps, etc.) won't be affected
- works on your LAN only, behind your router

## output

everything is printed live and also saved to `lanspy.log`
