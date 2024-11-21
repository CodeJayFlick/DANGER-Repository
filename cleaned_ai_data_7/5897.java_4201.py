class AddressArrayTableModel:
    def __init__(self, title: str, serviceProvider, program: 'Program', addresses: list['Address'], monitor=None):
        super().__init__(title, serviceProvider, program, monitor)
        self.addresses = addresses

    @property
    def addresses(self):
        return self._addresses

    @addresses.setter
    def addresses(self, value):
        self._addresses = value
        self.reload()
        self.fire_table_data_changed()

    def do_load(self, accumulator: dict['Address'], monitor=None) -> None:
        for address in self.addresses:
            accumulator[address] = address

class Program:
    pass  # placeholder for the Java class "Program"

class Address:
    pass  # placeholder for the Java class "Address"
