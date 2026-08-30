import time
from core.logger import setup_logger
from core.event_bus import EventBus
from core.config_loader import ConfigLoader

logger = setup_logger("Main")

def main():
    logger.info("Starting Smart Log Analyzer Platform v3.0...")
    
    # Load configuration
    config = ConfigLoader.load()
    
    # Initialize Event Bus
    event_bus = EventBus()
    
    # Initialize Threat Intel engine
    from utils.threat_intel import ThreatIntel
    ThreatIntel.initialize(config)
    
    # Initialize Responders (SOAR)
    from responses.firewall import FirewallResponse
    from responses.notifications import EmailResponse
    from responses.web_dashboard import WebDashboardResponse
    firewall = FirewallResponse(event_bus)
    notifier = EmailResponse(event_bus, admin_email=config.get("response", {}).get("admin_email", "admin@localhost"))
    web_dashboard = WebDashboardResponse(event_bus)
    
    # Initialize Engine (Sigma Rules)
    from engine.rule_engine import RuleEngine
    rule_engine = RuleEngine(event_bus, rules_dir=config.get("rules", {}).get("path", "rules/"))
    
    # Initialize Collectors (Ingestion)
    from collectors.log_collector import AuthLogCollector, SnortLogCollector
    from collectors.network_collector import NetworkCollector
    
    auth_log_path = config.get("logs", {}).get("auth_log", "auth.log")
    snort_log_path = config.get("logs", {}).get("snort_log", "snort.alert.fast")
    auth_collector = AuthLogCollector(event_bus, log_file=auth_log_path)
    snort_collector = SnortLogCollector(event_bus, log_file=snort_log_path)
    
    auth_collector.start()
    snort_collector.start()

    # Initialize File Integrity Monitoring (FIM) Collector
    fim_config = config.get("fim", {})
    if fim_config.get("enabled", False):
        from collectors.fim_collector import FIMCollector
        fim_targets = fim_config.get("targets", [])
        fim_interval = fim_config.get("check_interval", 60)
        fim_collector = FIMCollector(event_bus, targets=fim_targets, check_interval=fim_interval)
        fim_collector.start()

    # Initialize Network Sniffer/Collector
    net_config = config.get("network", {})
    net_enabled = net_config.get("enabled", True)
    net_interface = net_config.get("interface", "")
    
    net_collector = NetworkCollector(event_bus, interface=net_interface, enabled=net_enabled)
    net_collector.start()
    
    # Start the Web Dashboard server
    from api.server import start_server
    start_server(host="0.0.0.0", port=8000)
    
    logger.info("Platform initialized and running. Press Ctrl+C to stop.")
    logger.info("Web Dashboard available at http://0.0.0.0:8000")
    
    try:
        while True:
            time.sleep(1)
            # In a real scenario, Collectors would run in their own threads
            # and publish events to the EventBus.
    except KeyboardInterrupt:
        logger.info("Shutting down platform...")

if __name__ == "__main__":
    main()
