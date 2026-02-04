"""Tests for MISP Sigma rule generator."""

import pytest

from app.services.misp_rule_generator import SigmaRuleGenerator


def test_generate_simple_ip_rule():
    """Generate Sigma rule from IP IOCs."""
    generator = SigmaRuleGenerator()
    event_info = {
        'id': '12345',
        'uuid': 'test-uuid',
        'info': 'Test Campaign',
        'threat_level': 'High',
    }
    iocs = [
        {'value': '1.2.3.4'},
        {'value': '5.6.7.8'},
    ]

    result = generator.generate_rule(event_info, 'ip-dst', iocs, 'https://misp.test')

    assert result['ioc_type'] == 'ip-dst'
    assert result['ioc_count'] == 2
    assert 'rule' in result
    assert result['rule']['title'] == 'MISP: Test Campaign - IP Addresses'
    assert result['rule']['level'] == 'high'
    assert 'destination.ip' in str(result['rule']['detection'])


def test_generate_composite_filename_md5_rule():
    """Generate Sigma rule from composite filename|md5 IOCs."""
    generator = SigmaRuleGenerator()
    event_info = {
        'id': '12345',
        'uuid': 'test-uuid',
        'info': 'Malware Campaign',
        'threat_level': 'High',
    }
    iocs = [
        {'value': 'malware.exe|d41d8cd98f00b204e9800998ecf8427e'},
    ]

    result = generator.generate_rule(event_info, 'filename|md5', iocs, 'https://misp.test')

    assert result['ioc_type'] == 'filename|md5'
    assert 'selection_0' in result['rule']['detection']


def test_unsupported_ioc_type_raises():
    """Unsupported IOC type should raise ValueError."""
    generator = SigmaRuleGenerator()
    event_info = {'id': '1', 'info': 'Test', 'threat_level': 'High'}

    with pytest.raises(ValueError, match="Unsupported IOC type"):
        generator.generate_rule(event_info, 'unsupported-type', [], 'https://misp.test')
