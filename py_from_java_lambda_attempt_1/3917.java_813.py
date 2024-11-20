Here is the translation of the Java code into Python:

```Python
class CompareFunctionsFromListingAction:
    FUNCTION_MENU_SUBGROUP = "Function"

    def __init__(self, tool, owner):
        super().__init__(tool, owner)

        # this action is used as a global action--do not add it to the toolbar
        self.set_toolbar_data(None)

        # Guilty knowledge of other function-related menu items. See the FunctionPlugin for this value 
        self.menu_subgroup = "Z_End"
        icon = None  # we don't use icons in the Listing popup menu
        self.popup_menu_data = MenuData([self.POPUP_MENU_NAME], icon, self.FUNCTION_MENU_SUBGROUP, None, self.menu_subgroup)

    def is_add_to_popup(self, action_context):
        return isinstance(action_context, listing_action_context) and self.is_enabled_for_context(action_context)

    def is_valid_context(self, context):
        return isinstance(context, listing_action_context)

    def get_selected_functions(self, action_context):
        listing_context = listing_action_context(action_context)
        selection = listing_context.get_selection()
        program = listing_context.get_program()
        function_manager = program.get_function_manager()
        functions = set()
        for selected_function in function_manager.get_functions(selection, True):
            functions.add(selected_function)
        return functions
```

Note that this translation is not a direct conversion from Java to Python. Some changes were made to the code structure and naming conventions to conform to Python's style guidelines.