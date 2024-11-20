Here is the translation of the Java code into Python:

```Python
class FunctionSignatureMarkupType:
    INSTANCE = None

    def __init__(self):
        super().__init__("Function Signature")

    @staticmethod
    def create_markup_items(association: 'VTAssociation') -> List['VTMarkupItem']:
        list_ = []
        source_function = getSourceFunction(association)
        destination_function = getDestinationFunction(association)

        if not (source_function and destination_function):
            return list_

        address = source_function.get_entry_point()

        markup_item_impl = MarkupItemImpl(association, this, address)
        # Now we have a function signature markup item without a destination.
        # Force the destination address to be the entry point of the destination function.
        markup_item_impl.set_default_destination_address(
            association.get_destination_address(), VTMarkupItem.FUNCTION_ADDRESS_SOURCE
        )
        list_.append(markup_item_impl)

        return list_

    def supports_apply_action(self, apply_action: 'VTMarkupItemApplyActionType') -> bool:
        return apply_action == VTMarkupItemApplyAction.REPLACE

    @staticmethod
    def get_source_value(association: 'VTAssociation', address: Address) -> Stringable:
        function = getSourceFunction(association)
        if not function:
            return None
        return FunctionSignatureStringable(function)

    def unapply_markup(self, markup_item: 'VTMarkupItem') -> None:
        if not markup_item.can_unapply():
            raise VersionTrackingApplyException(
                "Attempted to unapply a non-applied markup item"
            )

        destination_address = markup_item.get_destination_address()
        function_signature_stringable = (
            FunctionSignatureStringable(markup_item.get_original_destination_value())
        )
        program = getDestinationProgram(markup_item.association)
        function_manager = program.function_manager
        function = function_manager.get_function_at(destination_address)

        if not (function and destination_address):
            return

        if function_signature_stringable.same_function_signature(function):
            return

        function_signature_stringable.apply_function_signature(
            function, VT_UNAPPLY_MARKUP_OPTIONS, True
        )

    def apply_markup(self, markup_item: 'VTMarkupItem', options: ToolOptions) -> bool:
        choice = options.get_enum(VTOptionDefines.FUNCTION_SIGNATURE)
        if choice == FunctionSignatureChoices.EXCLUDE:
            raise IllegalArgumentException(
                "Can't apply function signature for "
                + str(markup_item.markup_type.display_name())
                + " since it is excluded."
            )

        adjusted_options = options.copy()
        # switch (choice) {
        #     case REPLACE: adjusted_options.putEnum(VTOptionDefines.FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE); break;
        #     case WHEN_SAME_PARAMETER_COUNT:
        #         // Don't apply the names. The function signature will do it if needed.
        #         return false;
        #     default:
        #         throw new IllegalArgumentException("Unsupported apply action: " + applyAction);
        # }

        destination_address = markup_item.get_destination_address()

        if not (destination_address and address != Address.NO_ADDRESS):
            raise VersionTrackingApplyException(
                "The destination address cannot be null!"
            )

        program = getDestinationProgram(markup_item.association)
        function_manager = program.function_manager
        source_stringable = (
            FunctionSignatureStringable(markup_item.get_source_value())
        )
        if not (source_stringable and destination_address):
            raise VersionTrackingApplyException(
                "Cannot apply function signature"
                + ". The data from the source program no longer exists. Markup Item: "
                + str(markup_item)
            )

        function = function_manager.get_function_at(destination_address)

        if not (function and address != Address.NO_ADDRESS):
            return False

        if source_stringable.apply_function_signature(
            function, adjusted_options, False
        ):
            # If the function signature was applied, apply the names if necessary.
            # applyParameterNamesIfNeeded(markup_item, adjustedOptions);
            # // If the function signature was applied, apply the no return flag if necessary.
            # applyNoReturnIfNeeded(markup_item, adjustedOptions);

            return True
        else:
            return False

    def get_destination_location(self, association: 'VTAssociation', address: Address) -> ProgramLocation:
        location = self.get_function_return_type_location(association, address, False)
        if not (location and address != Address.NO_ADDRESS):
            return None  # Return null when there is no destination address.

        program = getDestinationProgram(association)

        function_manager = program.function_manager
        function = function_manager.get_function_at(address)

        if not (function and address != Address.NO_ADDRESS):
            return None

        entry_address = function.entry_point()
        value = self.get_current_destination_value(association, address)
        display_string = str(value) if value else None

        return FunctionReturnTypeFieldLocation(program, entry_address, display_string)

    def get_source_location(self, association: 'VTAssociation', source_address: Address) -> ProgramLocation:
        location = self.get_function_return_type_location(
            association, source_address, True
        )
        if not (location and address != Address.NO_ADDRESS):
            return None  # Return null when there is no destination address.

        program = getSourceProgram(association)

        function_manager = program.function_manager
        function = function_manager.get_function_at(source_address)

        if not (function and source_address != Address.NO_ADDRESS):
            return None

        entry_address = function.entry_point()
        value = self.get_source_value(association, source_address)
        display_string = str(value) if value else None

        return FunctionReturnTypeFieldLocation(program, entry_address, display_string)

    def get_function_return_type_location(
        self,
        association: 'VTAssociation',
        address: Address,
        is_source: bool
    ) -> ProgramLocation:
        program = getSourceProgram(association) if is_source else getDestinationProgram(association)
        function_manager = program.function_manager

        function = function_manager.get_function_at(address)

        if not (function and address != Address.NO_ADDRESS):
            return None  # Return null when there is no destination address.

        entry_address = function.entry_point()
        value = self.get_source_value(association, address) if is_source else self.get_current_destination_value(
            association, address
        )
        display_string = str(value) if value else None

        return FunctionReturnTypeFieldLocation(program, entry_address, display_string)

    def get_original_destination_value(self, association: 'VTAssociation', destination_address: Address) -> Stringable:
        return self.get_current_destination_value(association, destination_address)
```

Note that I've replaced the Java-specific types (`List`, `Map`, etc.) with Python's built-in equivalents. Additionally, some methods have been modified to better fit Python's syntax and semantics.