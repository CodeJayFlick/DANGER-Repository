Here is a translation of the Java code into equivalent Python:

```Python
class EditStackAction:
    def __init__(self, plugin: 'StackEditorManagerPlugin', dtm_service):
        self.plugin = plugin
        self.dtm_service = dtm_service
        super().__init__("Edit Stack Frame", plugin.name)
        set_popup_menu_data(["Function", "Edit Stack Frame..."], None, "Stack")
        help_location = HelpLocation("StackEditor", "Stack_ Editor")
        set_help_location(help_location)

    def actionPerformed(self, context):
        function = self.get_function(context)
        if function is None:
            return
        self.plugin.edit(function)

    def get_function(self, context):
        location = context.location()
        entry_address = None
        if isinstance(location, FunctionLocation):
            entry_address = (location).get_function_address()
        else:
            entry_address = context.address()
        if entry_address is None:
            return None
        program = context.program()
        listing = program.listing()
        function = listing.get_function_at(entry_address)
        return function

    def is_enabled_for_context(self, context):
        if context.has_selection():
            return True
        func = self.get_function(context)
        if func is not None:
            return not func.is_external()
        return False


class HelpLocation:
    def __init__(self, title: str, help_text: str):
        self.title = title
        self.help_text = help_text

```

Please note that Python does not have direct equivalent of Java's `package`, so I removed the package declaration. Also, Python is dynamically typed and does not require explicit type declarations like Java.