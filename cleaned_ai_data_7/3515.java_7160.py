class FunctionSignatureListingHover:
    NAME = "Function Signature Display"
    DESCRIPTION = f"Toggle whether function signature is displayed in a tooltip when the mouse hovers over a function signature."
    POPUP_PRIORITY = 20

    def __init__(self, tool):
        pass  # equivalent to Java constructor with no explicit code execution

    @property
    def name(self):
        return self.NAME

    @property
    def description(self):
        return self.DESCRIPTION

    @property
    def options_category(self):
        return "CATEGORY_ BROWSER_POPUPS"

    def get_hover_component(self, program, location, field_location, field):
        if not self.enabled or location is None:
            return None
        
        # equivalent to Java code for checking the class of ProgramLocation
        if isinstance(location, (FunctionSignatureFieldLocation, FunctionNameFieldLocation)):
            function_location = location  # assuming this will be used later

            entry_address = function_location.get_function_address()
            function_manager = program.function_manager
            function = function_manager.get_function_at(entry_address)

            tool_tip_text = ToolTipUtils.get_tool_tip_text(function, True)
            return JToolTip(tool_tip_text)  # equivalent to Java code for creating a tooltip


class FunctionSignatureFieldLocation:
    pass

class FunctionNameFieldLocation:
    pass

# assuming these classes are defined elsewhere in the program
