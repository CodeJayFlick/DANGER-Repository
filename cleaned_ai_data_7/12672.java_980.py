import serializable

class AddressLabelPair(serializable.Serializable):
    def __init__(self, addr: 'Address', label: str) -> None:
        self.addr = addr
        self.label = label

    @property
    def address(self) -> 'Address':
        return self.addr

    @property
    def label(self) -> str:
        return self.label


    def __eq__(self, other):
        if not isinstance(other, AddressLabelPair):
            return False
        
        if other is None or (hasattr(other, '_label') and not other._label):
            return False
        
        return self.addr == other.addr and self.label == other.label
