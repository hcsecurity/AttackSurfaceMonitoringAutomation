#!/usr/bin/env python3
"""Scan hosts and ports with nmap and write parsed results as JSON.

This program wraps the nmap binary (must be on PATH), allowing direct
execution through Python. It uses a TCP connect scan (-sT) so it runs
without raw socket privileges.
"""
import argparse
import json
import sys

import nmap


def run_nmap(hosts: str, ports: str, speed: int, disable_ping: bool = False) -> list[dict]:
    if speed not in range(1, 6):
        # it should be T1-T5
        raise ValueError(f"speed must be 1-5, got {speed}")
    pn = "-Pn" if disable_ping else ""
    arguments = " ".join(part for part in (f"-p{ports}", f"-T{speed}", pn, "-sT") if part)
    nm = nmap.PortScanner()
    nm.scan(hosts=hosts, arguments=arguments)

    results = []
    for host in nm.all_hosts():
        entry = {
            "host": host,
            "state": nm[host].state(),
            "ports": [],
        }
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto]):
                info = nm[host][proto][port]
                entry["ports"].append({
                    "port": port,
                    # right now only scanning TCP so no need to differentiate
                    #"protocol": proto,
                    "state": info.get("state"),
                    # currently prints the default service assigned
                    # for the port number, it doesn't scan it, so the
                    # name results are meaningless and equal for all IPs
                    #"name": info.get("name"),
                })
        results.append(entry)
    return results


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan IPs and their ports with nmap.")
    # ip list
    parser.add_argument(
        "targets", nargs="+", metavar="TARGET",
        help="Hosts to scan (IP, hostname, CIDR, or range).")
    # port list
    parser.add_argument(
        "-p", "--ports",
        help="Port spec passed to nmap.")
    parser.add_argument(
        "-o", "--output", default="output.json",
        help="Output JSON path (default: output.json).")
    # paranoia level
    parser.add_argument(
        "-T", "--speed", type=int, choices=range(1, 6), default=2, metavar="{1-5}",
        help="nmap timing template T1-T5 (default: 2).")
    # disable ping
    parser.add_argument(
        "-n", "--disable-ping", action="store_true",
        help="Skip host discovery (nmap -Pn).")
    return parser.parse_args()


def main():
    args = parse_args()
    results = run_nmap(" ".join(args.targets), args.ports, args.speed, args.disable_ping)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"wrote {len(results)} entries to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
