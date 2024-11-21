class MatchAddressRangeFilter:
    def get_association(self, match: 'VTMatch') -> 'VTAssociation':
        return match.get_association()
