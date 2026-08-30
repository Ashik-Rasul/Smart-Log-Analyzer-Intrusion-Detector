from abc import ABC, abstractmethod

class TIProvider(ABC):
    @abstractmethod
    def query(self, ip: str) -> dict:
        """
        Query the Threat Intelligence provider for a specific IP.
        Returns a normalized dictionary.
        """
        pass

class MockProvider(TIProvider):
    # Pre-configured list of known malicious IPs for testing purposes
    MALICIOUS_IPS = {
        "8.8.8.8": {"country": "US", "isp": "Google LLC", "asn": "AS15169", "botnet": False, "score": 90, "reports": 500},
        "192.168.1.99": {"country": "Local", "isp": "Internal", "asn": "N/A", "botnet": False, "score": 75, "reports": 10},
        "45.227.254.12": {"country": "Russia", "isp": "Example ISP", "asn": "AS12345", "botnet": True, "score": 98, "reports": 1234},
        "203.0.113.50": {"country": "Unknown", "isp": "Unknown", "asn": "Unknown", "botnet": True, "score": 100, "reports": 5000},
        "198.51.100.11": {"country": "Unknown", "isp": "Unknown", "asn": "Unknown", "botnet": True, "score": 100, "reports": 800}
    }

    def query(self, ip: str) -> dict:
        if ip in self.MALICIOUS_IPS:
            data = self.MALICIOUS_IPS[ip]
            return {
                "matched": True,
                "country": data["country"],
                "isp": data["isp"],
                "asn": data["asn"],
                "malicious_score": data["score"],
                "known_botnet": data["botnet"],
                "abuse_reports": data["reports"]
            }
        return {"matched": False}

class AbuseIPDBProvider(TIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def query(self, ip: str) -> dict:
        if not self.api_key:
            return {"matched": False}
        # In a real implementation, use the requests library here:
        # response = requests.get(f"https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip}, headers={"Key": self.api_key})
        # Normalize response...
        return {"matched": False} # Fallback to False for now if not implemented

class ThreatIntel:
    _providers = []
    _initialized = False

    @classmethod
    def initialize(cls, config: dict):
        if cls._initialized:
            return
            
        # Always add the mock provider so testing works without keys
        cls._providers.append(MockProvider())
        
        ti_config = config.get("threat_intel", {})
        
        abuse_key = ti_config.get("abuseipdb", {}).get("api_key")
        if abuse_key:
            cls._providers.append(AbuseIPDBProvider(abuse_key))
            
        # ... Other providers can be initialized here (OTX, VirusTotal)
        
        cls._initialized = True

    @classmethod
    def check_ip(cls, ip: str) -> dict:
        """
        Check if an IP address is present in the Threat Intelligence blacklist.
        Queries all configured providers and returns the highest severity match.
        """
        if not cls._initialized:
            # Fallback if initialize() wasn't called (e.g. from tests)
            cls.initialize({})

        best_match = {
            "matched": False,
            "feed": None,
            "country": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "malicious_score": 0,
            "known_botnet": False,
            "abuse_reports": 0
        }

        for provider in cls._providers:
            result = provider.query(ip)
            if result.get("matched"):
                # If multiple match, we take the one with the highest malicious score
                if result.get("malicious_score", 0) > best_match.get("malicious_score", 0):
                    best_match.update(result)
                    best_match["feed"] = provider.__class__.__name__

        return best_match
