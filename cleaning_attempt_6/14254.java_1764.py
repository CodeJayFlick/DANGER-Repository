import unittest
from dataclasses import dataclass

@dataclass
class Threat:
    type: str
    severity: int
    name: str


class SimpleThreatAwareSystem:
    def __init__(self, system_name, threats):
        self.system_name = system_name
        self.threats = threats

    def filtered(self) -> 'SimpleThreatAwareSystem':
        return self


def test_simple_threat_aware_system():
    rootkit = Threat(type='ROOTKIT', severity=1, name='Simple-Rootkit')
    trojan = Threat(type='TROJAN', severity=2, name='Simple-Trojan')

    threats = [rootkit, trojan]
    threat_aware_system = SimpleThreatAwareSystem('System-1', threats)

    rootkit_threat_aware_system = threat_aware_system.filtered().by(lambda x: x.type == 'ROOTKIT')

    assert len(rootkit_threat_aware_system.threats) == 1
    assert rootkit_threat_aware_system.threats[0] == rootkit


if __name__ == '__main__':
    test_simple_threat_aware_system()
