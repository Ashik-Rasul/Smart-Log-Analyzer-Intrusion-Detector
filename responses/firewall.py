import time
from core.logger import setup_logger
from core.event_bus import EventBus

logger = setup_logger(__name__)

class FirewallResponse:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.blocked_ips = {}
        self.event_bus.subscribe("alert_triggered", self.handle_alert)

    def handle_alert(self, alert: dict):
        action = alert.get("action")
        if action == "block_ip":
            ip = alert.get("event", {}).get("ip")
            if ip:
                self.block_ip(ip)

    def block_ip(self, ip: str):
        if ip in self.blocked_ips:
            return
            
        if ip in ["0.0.0.0", "127.0.0.1", "::1"]:
            logger.warning(f"SOAR ACTION: Ignoring block request for special IP: {ip}")
            return
            
        logger.warning(f"SOAR ACTION: Blocking IP {ip} via iptables")
        
        # Execute actual iptables command for Linux
        import subprocess
        subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        
        self.blocked_ips[ip] = time.time()
