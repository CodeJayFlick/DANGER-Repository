class VTMarkupItemDestinationAddressEditStatus:
    EDITABLE = ("This item's destination address is editable.")
    UNEDITABLE_FUNCTION_ENTRY_POINT = (
        "This item's destination address is based on the function's entry point and can't be edited."
    )
    UNEDITABLE_DATA_ADDRESS = (
        "This item's destination address is based on the address of data and can't be edited."
    )
    UNEDITABLE_UNAPPLIABLE_ASSOCIATION_STATUS = (
        "This markup item's Match status prevents its destination address from being edited."
    )
    UNEDITABLE_UNAPPLIABLE_MARKUP_STATUS = (
        "This markup item's status prevents its destination address from being edited."
    )

    def __init__(self, description):
        self.description = description

    @property
    def description(self):
        return self._description

    def __str__(self):
        return f"{self.__class__.__name__}: {self.description}"
