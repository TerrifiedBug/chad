"""Sigma rule generator from MISP IOCs."""

import logging
import uuid

logger = logging.getLogger(__name__)


class SigmaRuleGenerator:
    """Generate Sigma rules from MISP IOCs."""

    SIMPLE_IOC_MAPPING = {
        'ip-dst': {
            'logsource': {'category': 'network_connection'},
            'field': 'destination.ip',
            'modifier': None,
        },
        'ip-src': {
            'logsource': {'category': 'network_connection'},
            'field': 'source.ip',
            'modifier': None,
        },
        'domain': {
            'logsource': {'category': 'dns'},
            'field': 'dns.question.name',
            'modifier': None,
        },
        'hostname': {
            'logsource': {'category': 'dns'},
            'field': 'dns.question.name',
            'modifier': None,
        },
        'url': {
            'logsource': {'category': 'proxy'},
            'field': 'c-uri',
            'modifier': 'contains',
        },
        'md5': {
            'logsource': {'category': 'process_creation'},
            'field': 'Hashes',
            'modifier': 'contains',
        },
        'sha1': {
            'logsource': {'category': 'process_creation'},
            'field': 'Hashes',
            'modifier': 'contains',
        },
        'sha256': {
            'logsource': {'category': 'process_creation'},
            'field': 'Hashes',
            'modifier': 'contains',
        },
        'imphash': {
            'logsource': {'category': 'process_creation'},
            'field': 'Imphash',
            'modifier': None,
        },
        'filename': {
            'logsource': {'category': 'file_event'},
            'field': 'TargetFilename',
            'modifier': 'endswith',
        },
    }

    COMPOSITE_IOC_MAPPING = {
        'filename|md5': {
            'logsource': {'category': 'file_event'},
            'fields': [
                {'field': 'TargetFilename', 'modifier': 'endswith', 'part': 0},
                {'field': 'Hashes', 'modifier': 'contains', 'part': 1},
            ],
        },
        'filename|sha256': {
            'logsource': {'category': 'file_event'},
            'fields': [
                {'field': 'TargetFilename', 'modifier': 'endswith', 'part': 0},
                {'field': 'Hashes', 'modifier': 'contains', 'part': 1},
            ],
        },
        'filename|sha1': {
            'logsource': {'category': 'file_event'},
            'fields': [
                {'field': 'TargetFilename', 'modifier': 'endswith', 'part': 0},
                {'field': 'Hashes', 'modifier': 'contains', 'part': 1},
            ],
        },
    }

    IOC_TYPE_LABELS = {
        'ip-dst': 'IP Addresses',
        'ip-src': 'Source IPs',
        'domain': 'Domains',
        'hostname': 'Hostnames',
        'url': 'URLs',
        'md5': 'MD5 Hashes',
        'sha1': 'SHA1 Hashes',
        'sha256': 'SHA256 Hashes',
        'imphash': 'Import Hashes',
        'filename': 'Filenames',
        'filename|md5': 'Files (name + MD5)',
        'filename|sha256': 'Files (name + SHA256)',
        'filename|sha1': 'Files (name + SHA1)',
    }

    THREAT_LEVEL_MAP = {
        'High': 'high',
        'Medium': 'medium',
        'Low': 'low',
        'Undefined': 'informational',
    }

    def generate_rule(
        self,
        event_info: dict,
        ioc_type: str,
        iocs: list[dict],
        misp_url: str,
    ) -> dict:
        """Generate a Sigma rule from IOCs of a single type."""
        if ioc_type in self.COMPOSITE_IOC_MAPPING:
            return self._generate_composite_rule(event_info, ioc_type, iocs, misp_url)
        elif ioc_type in self.SIMPLE_IOC_MAPPING:
            return self._generate_simple_rule(event_info, ioc_type, iocs, misp_url)
        else:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")

    def _generate_simple_rule(
        self,
        event_info: dict,
        ioc_type: str,
        iocs: list[dict],
        misp_url: str,
    ) -> dict:
        """Generate rule for simple (non-composite) IOC types."""
        mapping = self.SIMPLE_IOC_MAPPING[ioc_type]
        values = [ioc['value'] for ioc in iocs]

        field_name = mapping['field']
        if mapping['modifier']:
            field_name = f"{field_name}|{mapping['modifier']}"

        rule = {
            'title': f"MISP: {event_info['info']} - {self._ioc_type_label(ioc_type)}",
            'id': str(uuid.uuid4()),
            'status': 'experimental',
            'description': (
                f"Detects activity related to {ioc_type} indicators from MISP event: "
                f"{event_info['info']} (Event ID: {event_info['id']})\n\n"
                f"This rule was auto-generated from MISP and may require tuning."
            ),
            'references': [f"{misp_url}/events/view/{event_info['id']}"],
            'tags': [
                f"misp.event-id={event_info['id']}",
                f"misp.threat-level={event_info['threat_level'].lower()}",
            ],
            'logsource': mapping['logsource'],
            'detection': {
                'selection': {field_name: values},
                'condition': 'selection'
            },
            'level': self._threat_level_to_sigma_level(event_info['threat_level']),
            'falsepositives': [
                f"Legitimate activity involving these {ioc_type} indicators",
                "Review and tune based on your environment"
            ],
        }

        return {
            'rule': rule,
            'ioc_type': ioc_type,
            'ioc_count': len(iocs),
            'ioc_values': values,
        }

    def _generate_composite_rule(
        self,
        event_info: dict,
        ioc_type: str,
        iocs: list[dict],
        misp_url: str,
    ) -> dict:
        """Generate rule for composite IOC types (e.g., filename|md5)."""
        mapping = self.COMPOSITE_IOC_MAPPING[ioc_type]

        detection = {'condition': ''}
        selection_names = []

        for i, ioc in enumerate(iocs):
            parts = ioc['value'].split('|')
            selection_name = f"selection_{i}"
            selection_names.append(selection_name)

            selection = {}
            for field_def in mapping['fields']:
                field_name = field_def['field']
                if field_def.get('modifier'):
                    field_name = f"{field_name}|{field_def['modifier']}"
                selection[field_name] = parts[field_def['part']]

            detection[selection_name] = selection

        detection['condition'] = ' or '.join(selection_names)

        rule = {
            'title': f"MISP: {event_info['info']} - {self._ioc_type_label(ioc_type)}",
            'id': str(uuid.uuid4()),
            'status': 'experimental',
            'description': (
                f"Detects activity related to {ioc_type} indicators from MISP event: "
                f"{event_info['info']} (Event ID: {event_info['id']})\n\n"
                f"This rule was auto-generated from MISP and may require tuning."
            ),
            'references': [f"{misp_url}/events/view/{event_info['id']}"],
            'tags': [
                f"misp.event-id={event_info['id']}",
                f"misp.threat-level={event_info['threat_level'].lower()}",
            ],
            'logsource': mapping['logsource'],
            'detection': detection,
            'level': self._threat_level_to_sigma_level(event_info['threat_level']),
            'falsepositives': [
                f"Legitimate activity involving these {ioc_type} indicators",
                "Review and tune based on your environment"
            ],
        }

        return {
            'rule': rule,
            'ioc_type': ioc_type,
            'ioc_count': len(iocs),
            'ioc_values': [ioc['value'] for ioc in iocs],
        }

    def _ioc_type_label(self, ioc_type: str) -> str:
        """Human-readable label for IOC type."""
        return self.IOC_TYPE_LABELS.get(ioc_type, ioc_type)

    def _threat_level_to_sigma_level(self, threat_level: str) -> str:
        """Map MISP threat level to Sigma level."""
        return self.THREAT_LEVEL_MAP.get(threat_level, 'medium')

    @classmethod
    def get_supported_types(cls) -> list[str]:
        """Get list of supported IOC types."""
        return list(cls.SIMPLE_IOC_MAPPING.keys()) + list(cls.COMPOSITE_IOC_MAPPING.keys())
