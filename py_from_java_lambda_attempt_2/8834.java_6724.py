Here is the translation of the Java code into Python:

```Python
class EolCommentMarkupType:
    INSTANCE = None

    def __init__(self):
        super().__init__("EOL Comment")

    @property
    def instance(self):
        if not self.INSTANCE:
            self.INSTANCE = self()
        return self.INSTANCE

    def get_code_unit_comment_type(self) -> int:
        return CodeUnit.EOL_COMMENT

    def get_location(self, association: 'VTAssociation', address: Address, is_source: bool) -> ProgramLocation:
        if address is None or address == Address.NO_ADDRESS:
            return None
        program = getSourceProgram(association) if is_source else getDestinationProgram(association)
        return EolCommentFieldLocation(program, address, None, None, 0, 0, 0)

    def get_comment_choice(self, options: 'ToolOptions') -> CommentChoices:
        comment_choice = options.get_enum(VTOptionDefines.END_OF_LINE_COMMENT, CommentChoices.APPEND_TO_EXISTING)
        return comment_choice

    def get_apply_action(self, options: 'ToolOptions') -> VTMarkupItemApplyActionType:
        comment_choice = self.get_comment_choice(options)
        if comment_choice == CommentChoices.APPEND_TO_EXISTING:
            return VTMarkupItemApplyActionType.ADD
        elif comment_choice == CommentChoices.OVERWRITE_EXISTING:
            return VTMarkupItemApplyActionType.REPLACE
        else:
            return None

    def convert_options_to_force_apply_of_markup_item(self, apply_action: 'VTMarkupItemApplyActionType', options: 'ToolOptions') -> Options:
        new_options = options.copy()
        if apply_action == VTMarkupItemApplyActionType.ADD:
            new_options.set_enum(VTOptionDefines.END_OF_LINE_COMMENT, CommentChoices.APPEND_TO_EXISTING)
        elif apply_action == VTMarkupItemApplyActionType.REPLACE:
            new_options.set_enum(VTOptionDefines.END_OF_LINE_COMMENT, CommentChoices.OVERWRITE_EXISTING)
        return new_options
```

Note that I've used Python's built-in `property` decorator to create a read-only property for the instance of this class. This is equivalent to Java's static final variable.

I have also replaced all the import statements with nothing as they are not necessary in Python and it seems like you're using some custom classes which would need to be defined elsewhere in your code.