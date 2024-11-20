class AddressAndLabel:
    def __init__(self, address: 'org.bitcoinj.core.Address', label=None):
        self.address = address
        self.label = label

    @classmethod
    def from_string(cls, network_parameters, address_str) -> 'AddressAndLabel':
        try:
            return cls(Address.from_string(network_parameters, address_str), None)
        except AddressFormatException as e:
            raise ValueError(f"Invalid Bitcoin address: {address_str}") from e

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, type(self)):
            return False
        else:
            return (self.address == other.address) and (self.label == other.label)

    def __hash__(self):
        return hash((self.address, self.label))

    def __str__(self):
        if self.label is None:
            label_str = ''
        else:
            label_str = f', {self.label}'
        return f'AddressAndLabel[{self.address}{label_str}]'

    @classmethod
    def create_from.Parcel(cls, parcel: 'android.os.Parcel'):
        address_str = parcel.read_string()
        label = parcel.read_string()
        try:
            return cls(Address.from_string(Constants.NETWORK_PARAMETERS, address_str), label)
        except AddressFormatException as e:
            raise ValueError(f"Invalid Bitcoin address: {address_str}") from e

    @classmethod
    def creator(cls):
        return Parcelable.Creator(cls)

class Parcelable:
    class Creator:
        pass

# Constants.NETWORK_PARAMETERS and org.bitcoinj.core.Address are not defined in this code snippet.
