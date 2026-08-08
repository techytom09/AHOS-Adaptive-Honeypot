"""
AHOS - STIX 2.1 Threat Intelligence Generator
Produces industry-standard threat intel reports
consumed by SIEMs and threat sharing platforms.
"""

import json
import os
import redis
from datetime import datetime, timezone
from stix2 import (
    Bundle, ThreatActor, AttackPattern,
    Indicator, Relationship, Identity,
    Malware, IPv4Address, DomainName
)

rd = redis.Redis(host='localhost', port=6379, decode_responses=True)

# ── MITRE ATT&CK Mappings ─────────────────────────────
ATTACK_PATTERNS = {
    "nmap_syn_scan": {
        "name":         "Network Service Discovery",
        "mitre_id":     "T1046",
        "description":  "Adversary scanning network services using SYN scan technique"
    },
    "masscan": {
        "name":         "Active Scanning",
        "mitre_id":     "T1595",
        "description":  "Mass internet scanning to identify open ports and services"
    },
    "linux_manual": {
        "name":         "Remote Services",
        "mitre_id":     "T1021",
        "description":  "Manual connection attempt from Linux host - likely human operator"
    },
    "windows_manual": {
        "name":         "Remote Services",
        "mitre_id":     "T1021",
        "description":  "Manual connection attempt from Windows host - likely human operator"
    },
    "shodan_crawler": {
        "name":         "Search Open Websites/Domains",
        "mitre_id":     "T1593",
        "description":  "Automated internet crawling via Shodan search engine"
    },
    "unknown_scanner": {
        "name":         "Active Scanning",
        "mitre_id":     "T1595",
        "description":  "Unknown automated scanning tool detected"
    },
}

THREAT_ACTOR_TYPES = {
    "critical": "nation-state",
    "high":     "criminal",
    "medium":   "hacker",
    "low":      "unknown",
}

LOG_DIR = "./logs"


class STIXGenerator:

    def __init__(self):
        os.makedirs(LOG_DIR, exist_ok=True)

        # AHOS as the reporting identity
        self.identity = Identity(
            name="AHOS - Adaptive Honeypot Orchestration System",
            identity_class="system",
            description="Automated threat intelligence from AHOS honeypot platform"
        )

    def _log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[STIX {ts}] {msg}")

    def generate(self, profile: dict) -> str:
        """Generate a STIX 2.1 bundle from an attacker profile."""
        src_ip  = profile.get("src_ip", "0.0.0.0")
        tool    = profile.get("detected_tool", "unknown_scanner")
        threat  = profile.get("threat_level", "low")
        human   = profile.get("is_human", False)

        self._log(f"Generating STIX report for {src_ip}...")

        attack_info  = ATTACK_PATTERNS.get(tool, ATTACK_PATTERNS["unknown_scanner"])
        actor_type   = THREAT_ACTOR_TYPES.get(threat, "unknown")

        # ── STIX Objects ──────────────────────────────
        threat_actor = ThreatActor(
            name             = f"Attacker-{src_ip.replace('.', '_')}",
            threat_actor_types = [actor_type],
            description      = f"Detected via AHOS honeypot. Tool: {tool}. Human: {human}",
            first_seen       = datetime.now(timezone.utc),
            sophistication   = "intermediate" if human else "minimal",
            labels           = [threat, tool],
        )

        attack_pattern = AttackPattern(
            name             = attack_info["name"],
            description      = attack_info["description"],
            external_references = [{
                "source_name": "mitre-attack",
                "external_id": attack_info["mitre_id"],
                "url": f"https://attack.mitre.org/techniques/{attack_info['mitre_id']}"
            }]
        )

        indicator = Indicator(
            name             = f"Malicious IP: {src_ip}",
            description      = f"IP observed conducting {attack_info['name']}",
            pattern          = f"[ipv4-addr:value = '{src_ip}']",
            pattern_type     = "stix",
            valid_from       = datetime.now(timezone.utc),
            indicator_types  = ["malicious-activity"],
            labels           = [tool, threat],
        )

        # ── Relationships ─────────────────────────────
        actor_uses_pattern = Relationship(
            relationship_type = "uses",
            source_ref        = threat_actor.id,
            target_ref        = attack_pattern.id,
        )

        actor_indicated_by = Relationship(
            relationship_type = "indicates",
            source_ref        = indicator.id,
            target_ref        = threat_actor.id,
        )

        # ── Bundle ────────────────────────────────────
        bundle = Bundle(
            self.identity,
            threat_actor,
            attack_pattern,
            indicator,
            actor_uses_pattern,
            actor_indicated_by,
        )

        # ── Save to file ──────────────────────────────
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename   = f"{LOG_DIR}/stix_{src_ip.replace('.','_')}_{timestamp}.json"

        with open(filename, "w") as f:
            f.write(bundle.serialize(pretty=True))

        self._log(f"✅ STIX bundle saved: {filename}")
        self._log(f"   Threat Actor: {threat_actor.name}")
        self._log(f"   ATT&CK:       {attack_info['mitre_id']} - {attack_info['name']}")
        self._log(f"   Indicator:    {src_ip}\n")

        # Store in Redis for dashboard
        rd.lpush("stix_reports", json.dumps({
            "filename":  filename,
            "src_ip":    src_ip,
            "tool":      tool,
            "threat":    threat,
            "mitre_id":  attack_info["mitre_id"],
            "generated": datetime.now().isoformat()
        }))

        # Also publish to pubsub for dashboard
        rd.publish("stix_reports", json.dumps({
            "filename":  filename,
            "src_ip":    src_ip,
            "tool":      tool,
            "threat":    threat,
            "mitre_id":  attack_info["mitre_id"],
            "generated": datetime.now().isoformat()
        }))

        return filename

    def start(self):
        """Subscribe to Redis and generate STIX reports on attacker detection."""
        pubsub = rd.pubsub()
        pubsub.subscribe("attacker_detected")
        generated = set()

        self._log("STIX Generator active - waiting for attacker profiles...\n")

        for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                profile = json.loads(message["data"])
                src_ip  = profile.get("src_ip")

                # One report per IP
                if src_ip in generated:
                    continue

                self.generate(profile)
                generated.add(src_ip)

            except Exception as e:
                self._log(f"Error: {e}")
                continue