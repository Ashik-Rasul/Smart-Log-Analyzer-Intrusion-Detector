import os
import yaml
import time
from collections import defaultdict
from core.logger import setup_logger
from core.event_bus import EventBus

logger = setup_logger(__name__)

class RuleEngine:
    def __init__(self, event_bus: EventBus, rules_dir: str = "rules/"):
        self.event_bus = event_bus
        self.rules_dir = rules_dir
        self.rules = []
        self.state = defaultdict(dict) # { rule_id: { ip: [timestamps] } }
        
        self.load_rules()
        self.event_bus.subscribe("normalized_event", self.evaluate_event)

    def load_rules(self):
        if not os.path.exists(self.rules_dir):
            logger.warning(f"Rules directory {self.rules_dir} not found.")
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        rule = yaml.safe_load(f)
                        self.rules.append(rule)
                        logger.info(f"Loaded rule: {rule.get('title')}")
                except Exception as e:
                    logger.error(f"Failed to load rule {filename}: {e}")

    def evaluate_event(self, event: dict):
        for rule in self.rules:
            # 1. Match Log Source
            if rule.get('logsource') != event.get('logsource'):
                continue
                
            # 2. Match Selection Condition
            selection = rule.get('detection', {}).get('selection', {})
            match = True
            for k, v in selection.items():
                if event.get(k) != v:
                    match = False
                    break
                    
            if not match:
                continue

            # 3. Check Thresholds (if applicable)
            threshold = rule.get('detection', {}).get('threshold')
            if threshold:
                field_val = event.get(threshold['field'])
                if not field_val:
                    continue
                
                rule_id = rule.get('id')
                now = time.time()
                
                if field_val not in self.state[rule_id]:
                    self.state[rule_id][field_val] = []
                
                self.state[rule_id][field_val].append(now)
                
                # Cleanup old events
                timeframe = threshold['timeframe']
                self.state[rule_id][field_val] = [
                    t for t in self.state[rule_id][field_val] 
                    if now - t <= timeframe
                ]
                
                if len(self.state[rule_id][field_val]) >= threshold['count']:
                    self._trigger_alert(rule, event)
                    # Clear state to avoid spamming
                    self.state[rule_id][field_val].clear()
            else:
                # No threshold, immediate trigger
                self._trigger_alert(rule, event)

    def _trigger_alert(self, rule: dict, event: dict):
        from utils.threat_intel import ThreatIntel
        from utils.risk_scorer import RiskScorer

        ip = event.get('ip')
        threat_intel_result = ThreatIntel.check_ip(ip) if ip else {"matched": False, "feed": None, "risk_increase": 0}
        
        level = rule.get('level', 'Low')
        risk_score = RiskScorer.calculate_score(level, threat_intel_result)

        alert = {
            "rule_title": rule.get('title'),
            "level": level,
            "action": rule.get('action'),
            "threshold": rule.get('detection', {}).get('threshold', {}),
            "event": event,
            "threat_intel": threat_intel_result,
            "risk_score": risk_score
        }
        logger.warning(f"ALERT TRIGGERED: {alert['rule_title']} - Level: {alert['level']} - Target: {ip} - Risk Score: {risk_score}")
        self.event_bus.publish("alert_triggered", alert)
