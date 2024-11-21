class ReferenceAddressPair:
    def __init__(self, source: 'Address', destination: 'Address'):
        if source is None:
            self.source = Address.NO_ADDRESS
        else:
            self.source = source
        
        if destination is None:
            self.destination = Address.NO_ADDRESS
        else:
            self.destination = destination

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value: 'Address'):
        if value is None:
            self._source = Address.NO_ADDRESS
        else:
            self._source = value

    @property
    def destination(self):
        return self._destination

    @destination.setter
    def destination(self, value: 'Address'):
        if value is None:
            self._destination = Address.NO_ADDRESS
        else:
            self._destination = value

    def __eq__(self, other):
        if not isinstance(other, ReferenceAddressPair):
            return False
        
        return (self.source == other.source) and (self.destination == other.destination)

    def __hash__(self):
        return hash((self.source.__hash__(), self.destination.__hash__()))
