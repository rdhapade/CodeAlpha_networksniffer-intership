from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import socket, os

class PacketAnalyzer:
    def __init__(self, outfile=None):
        self.outfile      = outfile
        self.pcount       = 0
        self.proto_stats  = defaultdict(int)
        self.flow_stats   = defaultdict(int)
        self.buf          = []

    def _log(self, msg):
        print(msg)
        if self.outfile:
            self.buf.append(msg)

    def _save(self):
        if self.outfile and self.buf:
            path = os.path.abspath(self.outfile)
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.buf))
            print(f"\n[+] Output saved to: {path}")

    def _parse(self, pkt):
        info = {}
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            info['eth'] = (eth.src, eth.dst, eth.type)
            self.proto_stats['Ethernet'] += 1

        if pkt.haslayer(IP):
            ip = pkt[IP]
            info['ip'] = (ip.src, ip.dst, ip.ttl, ip.proto)
            self.proto_stats['IPv4'] += 1
            self.flow_stats[f"{ip.src} -> {ip.dst}"] += 1

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = {k: bool(tcp.flags & v) for k, v in
                     {'URG':32,'ACK':16,'PSH':8,'RST':4,'SYN':2,'FIN':1}.items()}
            info['tcp'] = (tcp.sport, tcp.dport, tcp.seq, tcp.ack, flags)
            self.proto_stats['TCP'] += 1
            payload = bytes(tcp.payload)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info['udp'] = (udp.sport, udp.dport, udp.len)
            self.proto_stats['UDP'] += 1
            payload = bytes(udp.payload)
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            info['icmp'] = (icmp.type, icmp.code, icmp.chksum)
            self.proto_stats['ICMP'] += 1
            payload = bytes(icmp.payload)
        else:
            payload = b''

        info['raw'] = payload   
        return info

    def _display(self, info):
        if 'eth' in info:
            src,dst,ptype = info['eth']
            self._log(f"\nEthernet  {src} -> {dst}  type 0x{ptype:04x}")
        if 'ip' in info:
            s,d,ttl,proto = info['ip']
            self._log(f"IP        {s} -> {d}  ttl={ttl} proto={proto}")
        if 'tcp' in info:
            sp,dp,seq,ack,flags = info['tcp']
            fstr = ','.join(k for k,v in flags.items() if v)
            self._log(f"TCP       {sp}->{dp} seq={seq} ack={ack} flags={fstr}")
        elif 'udp' in info:
            sp,dp,l = info['udp']
            self._log(f"UDP       {sp}->{dp} len={l}")
        elif 'icmp' in info:
            t,c,chk = info['icmp']
            self._log(f"ICMP      type={t} code={c} chk=0x{chk:04x}")
        raw = info['raw']
        if raw:
            self._log("RAW       " + ' '.join(f"{b:02x}" for b in raw[:32]) +
                       (" ..." if len(raw) > 32 else ""))

    def handler(self, pkt):
        self.pcount += 1
        self._display(self._parse(pkt))

    def _stats(self):
        self._log("\n" + "="*50 + "\nSTATISTICS")
        self._log(f"Total packets : {self.pcount}")
        for p,c in self.proto_stats.items():
            pct = (c/self.pcount)*100 if self.pcount else 0
            self._log(f"  {p:<7}: {c} ({pct:.1f}%)")
        top = sorted(self.flow_stats.items(), key=lambda x:x[1], reverse=True)[:5]
        if top:
            self._log("\nTop flows:")
            for flow,c in top: self._log(f"  {flow}: {c}")
        self._log("Finished: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def capture(self, iface=None, cnt=10, flt=None):
        self._log(f"\n[+] Capturing iface={iface} count={cnt} filter={flt}")
        try:
            sniff(iface=iface, prn=self.handler, count=cnt, filter=flt, store=0)
        except KeyboardInterrupt:
            self._log("\n[!] Interrupted by user")
        except Exception as e:
            self._log(f"\n[!] Capture error: {e}")
        finally:
            self._stats(); self._save()

def main():
    print("="*60 + "\nNetwork Packet Analyzer\n" + "="*60)
    if input("Save output to file? (y/n): ").lower().startswith('y'):
        defname = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        outfile = input(f"Filename (default {defname}): ").strip() or defname
    else:
        outfile = None

    iface = input("Interface (blank=default): ").strip() or None
    try:
        cnt = int(input("Packets to capture (default 10): ") or 10)
    except: cnt = 10
    bpf = input("BPF filter (blank = none): ").strip() or None

    PacketAnalyzer(outfile).capture(iface, cnt, bpf)

if __name__ == "__main__":
    try:
        import scapy
        print("[+] Scapy detected – full functionality.")
    except ImportError:
        print("[!] Scapy missing → install:  pip install scapy")
    main()
