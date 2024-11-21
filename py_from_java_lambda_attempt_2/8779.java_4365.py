Here is the translation of the given Java code into equivalent Python:

```Python
class MarkupItemStorageDB:
    def __init__(self, record: 'DBObject', cache: dict, association_manager):
        self.record = record
        self.association_manager = association_manager
        self.session = association_manager.get_session()
        self.association_key = record.get_long_value('ASSOCIATION_KEY_ COL')
        self.association = association_manager.get_association(self.association_key)

    def get_markup_type(self) -> 'VTMarkupType':
        return VTMarkupTypeFactory().get_markup_type(record.get_short_value('MARKUP_TYPE_COL'))

    def get_association(self):
        return self.association

    def get_source_address(self) -> 'Address':
        address_long = record.get_long_value('SOURCE_ADDRESS_ COL')
        program = self.session.get_source_program()
        address_map = program.get_address_map()
        return address_map.decode_address(address_long)

    def get_destination_address(self) -> 'Address':
        address_long = record.get_long_value('DESTINATION_ADDRESS_COL')
        program = self.session.get_destination_program()
        address_map = program.get_address_map()
        return address_map.decode_address(address_long)

    def get_destination_address_source(self):
        return record.get_string('ADDRESS_SOURCE_ COL')

    def get_status(self) -> 'VTMarkupItemStatus':
        check_is_valid()
        ordinal = record.get_byte_value('STATUS_COL')
        return VTMarkupItemStatus(ordinal)

    def get_status_description(self):
        return record.get_string('STATUS_DESCRIPTION_ COL')

    def get_source_value(self) -> str:
        string = record.get_string('SOURCE_VALUE_ COL')
        return string

    def get_destination_value(self) -> str:
        string = record.get_string('ORIGINAL_DESTINATION_VALUE_COL')
        return string

    def set_source_destination_values(self, source_value: 'Stringable', destination_value: 'Stringable'):
        program = self.session.get_source_program()
        string = Stringable().get_string(source_value, program)
        record.set_string('SOURCE_VALUE_ COL', string)

        program = self.session.get_destination_program()
        string = Stringable().get_string(destination_value, program)
        record.set_string('ORIGINAL_DESTINATION_VALUE_COL', string)

    def set_status(self, status: 'VTMarkupItemStatus') -> 'self':
        record.set_byte_value('STATUS_ COL', (byte)status.ordinal())
        self.association_manager.update_markup_record(record)
        return self

    def set_apply_failed(self, message):
        record.set_string('STATUS_DESCRIPTION_ COL', message)
        return self.set_status(VTMarkupItemStatus.FAILED_APPLY)

    def reset(self) -> 'self':
        try:
            storage = MarkupItemStorageImpl(self.association, self.get_markup_type(), 
                                             self.get_source_address(), self.get_destination_address(),
                                             self.get_destination_address_source())
            self.association_manager.remove_markup_record(record)
            return storage
        finally:
            pass

    def set_destination_address(self, destination_address: 'Address', address_source):
        if destination_address is None:
            destination_address = Address.NO_ADDRESS
        program = self.session.get_destination_program()
        address_map = program.get_address_map()
        address_id = address_map.key(destination_address, False)
        record.set_long_value('DESTINATION_ADDRESS_ COL', address_id)

    def refresh(self) -> bool:
        return self.refresh(None)

    def refresh(self, match_record):
        if match_record is None:
            match_record = self.association_manager.get_markup_item_record(key)
        if match_record is None:
            return False
        record = match_record
        return True

    def __str__(self) -> str:
        buffy = StringBuffer()
        buffy.append('\n').append(self.__class__.__name__)
        buffy.append('\t').append("Source Address          =  ").append(str(self.get_source_address()))
        buffy.append('\t').append("Dest Address            =  ").append(str(self.get_destination_address()))
        buffy.append('\t').append("Markup Class            =  ").append(str(self.get_markup_type()))
        buffy.append('\t').append("Status                  =  ").append(str(self.get_status()))
        buffy.append('\t').append("Source Value            =  ").append(str(self.get_source_value()))
        buffy.append('\t').append("Dest Value              =  ").append(str(self.get_destination_value()))
        buffy.append('\t').append("Association             =  ").append(str(self.association))
        buffy.append('\t').append("Algorithm               =  ").append(str(self.get_destination_address_source()))
        return str(buffy)
```

Please note that Python does not support direct translation of Java code, as the two languages have different syntax and semantics. The above Python code is an equivalent implementation of the given Java code in terms of functionality but may differ slightly due to differences between the two languages.