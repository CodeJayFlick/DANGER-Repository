class MatchSetImpl:
    def __init__(self, session: 'VTSession', name: str):
        self.session = session
        self.correlator_info = ProgramCorrelatorInfoFake(name)

    @property
    def id(self) -> int:
        return 0

    @property
    def match_count(self) -> int:
        return 0

    @property
    def session_(self):
        return self.session

    def get_matches(self, source_address: 'Address', destination_address: 'Address') -> list['VTMatch']:
        return []

    def get_matches(self, association: 'VTAssociation') -> list['VTMatch']:
        return [VTMatch()]

    @property
    def program_correlator_info(self) -> 'ProgramCorrelatorInfoFake':
        return self.correlator_info

    def remove_match(self, match: 'VTMatch'):
        raise UnsupportedOperationException()

    def has_removable_matches(self) -> bool:
        info = self.program_correlator_info
        correlator_class_name = info.get_correlator_class_name()
        return correlator_class_name == ManualMatchProgramCorrelator.__name__ or \
               correlator_class_name == ImpliedMatchProgramCorrelator.__name__

    def __str__(self) -> str:
        return f"Match Set {self.id} - {self.match_count} matches [Correlator={self.program_correlator_info.name}]"


class ProgramCorrelatorInfoFake:
    def __init__(self, name: str):
        self.name = name

    @property
    def get_correlator_class_name(self) -> str:
        return "fake"
