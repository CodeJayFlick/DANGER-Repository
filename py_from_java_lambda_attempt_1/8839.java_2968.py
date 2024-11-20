Here is the translation of the given Java code into equivalent Python:

```Python
class PlateCommentMarkupType:
    INSTANCE = None  # Singleton instance

    def __init__(self):
        super().__init__("Plate Comment")

    @property
    def instance(self):
        if not self.INSTANCE:
            self.INSTANCE = PlateCommentMarkupType()
        return self.INSTANCE

    def get_code_unit_comment_type(self) -> int:
        return CodeUnit.PLATE_COMMENT  # Assuming a constant is defined elsewhere in the codebase.

    def get_location(self, association: 'VTAssociation', address: Address, is_source: bool):
        if not (address and isinstance(address, Address)):
            return None
        program = self.get_program(association, is_source)
        return PlateFieldLocation(program, address, None, 0, 0, None, -1)

    def get_comment_choice(self, options: 'ToolOptions') -> CommentChoices:
        comment_choice = options.get_enum(VTOptionDefines.PLATE_COMMENT, CommentChoices.APPEND_TO_EXISTING)
        return comment_choice

    def get_apply_action(self, options: 'ToolOptions'):
        comment_choice = self.get_comment_choice(options)
        if comment_choice == CommentChoices.APPEND_TO_EXISTING:
            return VTMarkupItemApplyActionType.ADD
        elif comment_choice == CommentChoices.OVERWRITE_EXISTING:
            return VTMarkupItemApplyActionType.REPLACE
        else:
            return None

    def validate_destination_address(self, association: 'VTAssociation', source_address: Address,
                                      suggested_destination_address: Address):
        if source_address and source_address.equals(association.get_source_address()):
            return association.get_destination_address()
        return suggested_destination_address

    @staticmethod
    def convert_options_to_force_apply_of_markup_item(apply_action: VTMarkupItemApplyActionType, options: 'ToolOptions') -> Options:
        new_options = options.copy()
        if apply_action == VTMarkupItemApplyActionType.ADD:
            new_options.set_enum(VTOptionDefines.PLATE_COMMENT, CommentChoices.APPEND_TO_EXISTING)
        elif apply_action == VTMarkupItemApplyActionType.REPLACE:
            new_options.set_enum(VTOptionDefines.PLATE_COMMENT, CommentChoices.OVERWRITE_EXISTING)
        return new_options

    def create_markup_items(self, association: 'VTAssociation') -> List['VTMarkupItem']:
        markup_items = super().create_markup_items(association)
        for item in markup_items:
            if item.get_source_address() == association.get_source_address():
                # Set Plate destination to destination function's entry point.
                item.set_default_destination_address(association.get_destination_address(), VTMarkupItem.FUNCTION_ADDRESS_SOURCE)
        return markup_items
```

Please note that Python does not support direct translation of Java code. It is necessary to manually translate the given Java code into equivalent Python, considering the differences between both languages and their respective syntaxes.