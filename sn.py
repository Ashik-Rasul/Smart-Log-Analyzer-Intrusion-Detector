#!/usr/bin/env python3

import time
import re
import os
import subprocess
import signal
import sys
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "/var/log/snort/snort.alert.fast"
BLACKLIST_FILE = "blacklist.txt"

TEMP_BLOCK_TIME = timedelta(hours=2)

# Control flag for clean shutdown
running = True

def stop_handler(sig, frame):
    global running
    print("\n[+] Stopping IDS Monitor...")
    running = False

signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)

attack_patterns = {
    "SYN_SCAN": r"SYN",
    "TCP_CONNECT_SCAN": r"TCP",
    "FIN_SCAN": r"FIN",
    "XMAS_SCAN": r"XMAS",
    "NULL_SCAN": r"NULL",
    "UDP_SCAN": r"UDP",
    "SSH_BRUTE_FORCE": r"SSH",
    "HTTP_DDOS": r"HTTP",
    "PING_FLOOD": r"ICMP",
    "SQL_INJECTION": r"OR 1=1",
    "XSS_ATTACK": r"<script>",
    "FTP_BRUTE_FORCE": r"FTP",
    "DNS_TUNNELING": r"DNS",
    "SMB_EXPLOIT": r"445"
}

severity_score = {
    "SYN_SCAN": 3,
    "TCP_CONNECT_SCAN": 3,
    "FIN_SCAN": 3,
    "XMAS_SCAN": 4,
    "NULL_SCAN": 4,
    "UDP_SCAN": 4,
    "SSH_BRUTE_FORCE": 8,
    "HTTP_DDOS": 9,
    "PING_FLOOD": 7,
    "SQL_INJECTION": 9,
    "XSS_ATTACK": 6,
    "FTP_BRUTE_FORCE": 7,
    "DNS_TUNNELING": 9,
    "SMB_EXPLOIT": 10
}

ip_regex = r'(\d+\.\d+\.\d+\.\d+)'

packet_counter = defaultdict(int)
blocked_ips = {}
permanent_block = set()
ip_attack_history = defaultdict(set)

total_attacks = 0


# ---------------------------
# FIREWALL FUNCTIONS
# ---------------------------

def block_ip(ip):
    # Prevent duplicate rules
    check = subprocess.call(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if check != 0:
        subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])


def unblock_ip(ip):
    subprocess.call(
        ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


# ---------------------------
# FILE FUNCTIONS
# ---------------------------

def ensure_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        open(BLACKLIST_FILE, "w").close()


def write_blacklist(ip, attack, count):

    ensure_blacklist()

    if attack in ip_attack_history[ip]:
        return

    ip_attack_history[ip].add(attack)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{now} {ip} {attack} {count}\n")


# ---------------------------
# DISPLAY
# ---------------------------

def severity_label(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"


def dashboard():
    os.system("clear" if os.name == "posix" else "cls")

    print("======================================")
    print(" SNORT IPS LIVE ATTACK DASHBOARD ")
    print("======================================\n")

    print(f"Total Attacks Detected : {total_attacks}\n")

    print("Top Attackers\n")

    sorted_ips = sorted(packet_counter.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:5]:
        if ip in permanent_block:
            status = "PERMANENT BLOCK"
        elif ip in blocked_ips:
            status = "TEMP BLOCK"
        else:
            status = "ACTIVE"

        print(f"{ip} | packets:{count} | {status}")

    print("\nRecent Attack Types\n")

    for ip, attacks in ip_attack_history.items():
        for attack in attacks:
            score = severity_score.get(attack, 1)
            label = severity_label(score)
            print(f"{ip} → {attack} | score:{score} | {label}")

    print("\nMonitoring:", LOG_FILE)


# ---------------------------
# MAIN
# ---------------------------

print("[+] Starting Snort IDS Monitor...\n")

try:
    with open(LOG_FILE, "r") as logfile:

        logfile.seek(0, 2)  # move to end

        while running:

            line = logfile.readline()

            if not line:
                time.sleep(0.5)
                continue

            ip_match = re.findall(ip_regex, line)

            if not ip_match:
                continue

            attacker_ip = ip_match[0]

            for attack, pattern in attack_patterns.items():

                if re.search(pattern, line, re.IGNORECASE):

                    packet_counter[attacker_ip] += 1
                    total_attacks += 1

                    score = severity_score.get(attack, 1)

                    print(f"[ATTACK] {attack} | {attacker_ip} | score:{score}")

                    if attacker_ip not in blocked_ips and attacker_ip not in permanent_block:

                        block_ip(attacker_ip)
                        blocked_ips[attacker_ip] = datetime.now()

                        write_blacklist(attacker_ip, attack, packet_counter[attacker_ip])

                    elif attacker_ip in blocked_ips:

                        if attack not in ip_attack_history[attacker_ip]:

                            block_ip(attacker_ip)
                            permanent_block.add(attacker_ip)

                            write_blacklist(attacker_ip, attack, packet_counter[attacker_ip])

            dashboard()

            # Handle temporary unblock
            for ip, block_time in list(blocked_ips.items()):

                if datetime.now() - block_time > TEMP_BLOCK_TIME and ip not in permanent_block:

                    print(f"[+] Unblocking {ip}")
                    unblock_ip(ip)
                    del blocked_ips[ip]

except FileNotFoundError:
    print(f"[ERROR] Log file not found: {LOG_FILE}")

except Exception as e:
    print(f"[ERROR] {e}")

finally:
    print("[+] IDS Monitor stopped cleanly.")
