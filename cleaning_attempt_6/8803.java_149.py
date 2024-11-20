class MarkupItemStorage:
    def __init__(self, association: 'VTAssociation', markup_type: 'VTMarkupType', source_address: int):
        self._association = association
        self._markup_type = markup_type
        self._source_address = source_address

    @property
    def association(self) -> 'VTAssociation':
        return self._association

    @property
    def markup_type(self) -> 'VTMarkupType':
        return self._markup_type

    @property
    def source_address(self) -> int:
        return self._source_address

    def get_destination_address(self):
        return self._destination_address

    def set_destination_address(self, destination_address: int, address_source: str):
        self._destination_address = destination_address
        self._address_source = address_source

    @property
    def status(self) -> 'VTMarkupItemStatus':
        return self._status

    @status.setter
    def status(self, value: 'VTMarkupItemStatus'):
        self._status = value

    @property
    def destination_address_source(self):
        return self._address_source

    @destination_address_source.setter
    def destination_address_source(self, value: str):
        self._address_source = value

    @property
    def source_value(self) -> 'Stringable':
        return self._source_value

    @source_value.setter
    def source_value(self, value: 'Stringable'):
        self._source_value = value

    @property
    def destination_value(self) -> 'Stringable':
        return self._destination_value

    @destination_value.setter
    def destination_value(self, value: 'Stringable'):
        self._destination_value = value

    def set_source_destination_values(self, source_value: 'Stringable', destination_value: 'Stringable'):
        self.source_value = source_value
        self.destination_value = destination_value

    def apply_status(self):
        return f"Status applied with {self.status}"

    def reset(self) -> 'MarkupItemStorage':
        # Resetting the status and other attributes here if needed.
        pass

    def __str__(self):
        buffy = ''
        buffy += '\n' + self.__class__.__name__ + '\n'
        buffy += '\tSource Address          =  {}\n'.format(self.source_address)
        buffy += '\tMarkup Type             =  {}\n'.format(self.markup_type)
        buffy += '\tStatus                  =  {}\n'.format(self.status)
        buffy += '\tDestination Address      =  {}\n'.format(self.get_destination_address())
        buffy += '\tAddress Source           =  {}\n'.format(self.destination_address_source)

        return buffy
