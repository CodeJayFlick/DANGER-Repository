class SimpleThreat:
    def __init__(self, threat_type: 'ThreatType', id: int, name: str):
        self.threat_type = threat_type
        self.id = id
        self.name = name

    @property
    def name(self) -> str:
        return self.name

    @property
    def id(self) -> int:
        return self.id

    @property
    def type(self) -> 'ThreatType':
        return self.threat_type


class ThreatType:
    pass  # You need to define this class further based on your requirements.
