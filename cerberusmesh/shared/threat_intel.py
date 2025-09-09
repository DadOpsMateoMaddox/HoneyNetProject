"""
CerberusMesh Threat Intelligence Integration

Supports integration with external threat intelligence platforms:
- MISP (Malware Information Sharing Platform)
- STIX/TAXII feeds
- Custom threat feeds
"""

import requests
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

class ThreatIntelClient:
    """Client for integrating with threat intelligence platforms."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize threat intelligence client.

        Args:
            config: Configuration dictionary containing API keys and endpoints
        """
        self.config = config
        self.session = requests.Session()
        self.session.timeout = 30

        # Configure authentication
        if 'api_key' in config:
            self.session.headers.update({
                'Authorization': f'Bearer {config["api_key"]}',
                'Content-Type': 'application/json'
            })

    def fetch_misp_events(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Fetch recent events from MISP.

        Args:
            days_back: Number of days to look back for events

        Returns:
            List of MISP events
        """
        try:
            misp_url = self.config.get('misp_url')
            if not misp_url:
                logger.warning("MISP URL not configured")
                return []

            # Calculate date filter
            since_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')

            params = {
                'returnFormat': 'json',
                'date_from': since_date,
                'published': 1  # Only published events
            }

            response = self.session.get(f"{misp_url}/events/index", params=params)
            response.raise_for_status()

            events = response.json()
            logger.info(f"Fetched {len(events)} events from MISP")
            return events

        except Exception as e:
            logger.error(f"Failed to fetch MISP events: {e}")
            return []

    def fetch_stix_bundle(self, collection_url: str) -> Optional[Dict[str, Any]]:
        """Fetch STIX bundle from TAXII server.

        Args:
            collection_url: TAXII collection URL

        Returns:
            STIX bundle or None if failed
        """
        try:
            response = self.session.get(collection_url)
            response.raise_for_status()

            bundle = response.json()
            logger.info(f"Fetched STIX bundle from {collection_url}")
            return bundle

        except Exception as e:
            logger.error(f"Failed to fetch STIX bundle: {e}")
            return None

    def fetch_custom_feed(self, feed_url: str) -> List[Dict[str, Any]]:
        """Fetch indicators from custom threat feed.

        Args:
            feed_url: URL of the threat feed

        Returns:
            List of threat indicators
        """
        try:
            response = self.session.get(feed_url)
            response.raise_for_status()

            # Try to parse as JSON first
            try:
                data = response.json()
                if isinstance(data, list):
                    indicators = data
                else:
                    indicators = [data]
            except json.JSONDecodeError:
                # If not JSON, treat as text and split by lines
                lines = response.text.strip().split('\n')
                indicators = [{'value': line.strip(), 'type': 'unknown'} for line in lines if line.strip()]

            logger.info(f"Fetched {len(indicators)} indicators from {feed_url}")
            return indicators

        except Exception as e:
            logger.error(f"Failed to fetch custom feed: {e}")
            return []

    def enrich_indicator(self, indicator: str, indicator_type: str = 'ip') -> Dict[str, Any]:
        """Enrich a threat indicator with additional context.

        Args:
            indicator: The indicator value (IP, domain, hash, etc.)
            indicator_type: Type of indicator

        Returns:
            Enriched indicator data
        """
        enriched = {
            'value': indicator,
            'type': indicator_type,
            'enrichment': {},
            'timestamp': datetime.now().isoformat()
        }

        try:
            # Shodan enrichment for IPs
            if indicator_type == 'ip' and self.config.get('shodan_api_key'):
                shodan_data = self._enrich_with_shodan(indicator)
                if shodan_data:
                    enriched['enrichment']['shodan'] = shodan_data

            # WHOIS enrichment for domains
            if indicator_type == 'domain':
                whois_data = self._enrich_with_whois(indicator)
                if whois_data:
                    enriched['enrichment']['whois'] = whois_data

            # VirusTotal enrichment
            if self.config.get('virustotal_api_key'):
                vt_data = self._enrich_with_virustotal(indicator, indicator_type)
                if vt_data:
                    enriched['enrichment']['virustotal'] = vt_data

        except Exception as e:
            logger.error(f"Failed to enrich indicator {indicator}: {e}")

        return enriched

    def _enrich_with_shodan(self, ip: str) -> Optional[Dict[str, Any]]:
        """Enrich IP with Shodan data."""
        try:
            api_key = self.config.get('shodan_api_key')
            if not api_key:
                return None

            response = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={'key': api_key},
                timeout=10
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.debug(f"Shodan enrichment failed for {ip}: {e}")
            return None

    def _enrich_with_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """Enrich domain with WHOIS data."""
        try:
            import whois
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except Exception as e:
            logger.debug(f"WHOIS enrichment failed for {domain}: {e}")
            return None

    def _enrich_with_virustotal(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Enrich indicator with VirusTotal data."""
        try:
            api_key = self.config.get('virustotal_api_key')
            if not api_key:
                return None

            # Map indicator types to VT endpoints
            vt_endpoints = {
                'ip': 'ip_addresses',
                'domain': 'domains',
                'hash': 'files'
            }

            endpoint = vt_endpoints.get(indicator_type)
            if not endpoint:
                return None

            headers = {'x-apikey': api_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.debug(f"VirusTotal enrichment failed for {indicator}: {e}")
            return None

    def export_to_stix(self, indicators: List[Dict[str, Any]], output_file: str):
        """Export indicators to STIX format.

        Args:
            indicators: List of indicator dictionaries
            output_file: Path to output STIX file
        """
        try:
            stix_bundle = {
                "type": "bundle",
                "id": f"bundle--{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "objects": []
            }

            for indicator in indicators:
                stix_indicator = {
                    "type": "indicator",
                    "id": f"indicator--{indicator.get('id', 'unknown')}",
                    "created": indicator.get('timestamp', datetime.now().isoformat()),
                    "modified": indicator.get('timestamp', datetime.now().isoformat()),
                    "pattern": f"[{indicator.get('type')}:value = '{indicator['value']}']",
                    "pattern_type": "stix",
                    "valid_from": indicator.get('timestamp', datetime.now().isoformat())
                }
                stix_bundle["objects"].append(stix_indicator)

            # Write to file
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump(stix_bundle, f, indent=2)

            logger.info(f"Exported {len(indicators)} indicators to STIX file: {output_file}")

        except Exception as e:
            logger.error(f"Failed to export to STIX: {e}")

# Example usage
if __name__ == "__main__":
    config = {
        'misp_url': 'https://misp.example.com',
        'api_key': 'your-misp-api-key',
        'shodan_api_key': 'your-shodan-key',
        'virustotal_api_key': 'your-vt-key'
    }

    client = ThreatIntelClient(config)

    # Fetch MISP events
    events = client.fetch_misp_events(days_back=7)
    print(f"Fetched {len(events)} MISP events")

    # Enrich an IP
    enriched = client.enrich_indicator('8.8.8.8', 'ip')
    print(f"Enriched indicator: {enriched}")

    # Export to STIX
    client.export_to_stix([enriched], 'threat_intel.stix.json')
