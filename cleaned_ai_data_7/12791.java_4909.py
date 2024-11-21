class LinearDataAddressCorrelation:
    def __init__(self, source_data: 'Data', destination_data: 'Data'):
        self.source_data = source_data
        self.destination_data = destination_data

    def get_correlated_destination_range(self, source_address: int, monitor=None) -> tuple:
        offset = source_address.get_offset()
        base = self.source_data.address.offset
        delta = offset - base
        address = self.destination_data.address + delta
        return (address, address)

    def get_name(self):
        return "LinearDataAddressCorrelation"
