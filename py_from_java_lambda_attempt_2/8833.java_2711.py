Here is the translation of the Java code into Python:

```Python
class DataTypeMarkupType:
    def __init__(self):
        super().__init__("Data Type")

    @staticmethod
    def instance():
        return DataTypeMarkupType()

    def create_markup_items(self, association: 'VTAssociation') -> List['VTMarkupItem']:
        list_ = []
        session = association.get_session()
        source_program = session.get_source_program()
        listing = source_program.get_listing()
        address = association.get_source_address()
        data = listing.get_data_at(address)

        if data is None:
            return []

        markup_item = MarkupItemImpl(association, self, address)
        list_.append(markup_item)

        destination_address = association.get_destination_address()

        if destination_address is not None:
            markup_item.set_default_destination_address(destination_address,
                                                         VTMarkupItem.DATA_ADDRESS_SOURCE)

        return list_

    def validate_destination_address(self, association: 'VTAssociation', source_address: Address,
                                       suggested_destination_address: Address) -> Address:
        return association.get_destination_address()

    @staticmethod
    def get_replace_data_choices(options):
        try:
            replace_choice = options.get_enum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
                                               ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)
        except ClassCastException as e:
            options.remove_option(VTOptionDefines.DATA_MATCH_DATA_TYPE)
            return options.get_enum(VTOptionDefines.DATA_MATCH_DATA_TYPE,
                                    ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY)

    def set_data_type(self, program: 'Program', start_address: Address, data_type: DataType,
                      length: int, replace_choice: VTMatchApplyChoices.ReplaceDataChoices) -> bool:
        listing = program.get_listing()
        original_data = listing.get_data_at(start_address)
        if original_data is None:
            raise VersionTrackingApplyException("Data Type Markup cannot be applied since there isn't Data at the destination address!")

        try:
            listing.clear_code_units(start_address, length - 1, False)  # Clear the necessary code units.
        except CodeUnitInsertionException as e:
            self.try_to_restore_original_data(listing, start_address, original_data.get_data_type(),
                                               original_data.get_length())
            raise e

    def try_to_restore_original_data(self, listing: 'Listing', address: Address,
                                      data_type: DataType, length: int):
        # If we get an error trying to put the original back then dump a message and bail out.
        Msg.error(self, "Couldn't restore data type of {} after failing to set data type markup at {}.".format(data_type.get_name(), address))
    ```

Please note that Python does not support static methods or classes. Also, Java's `List` is equivalent to Python's list.