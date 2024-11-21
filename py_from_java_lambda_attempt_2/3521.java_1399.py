Here is the translation of the Java code to Python:
```
import ghidra_app

class ReferenceListingHoverPlugin:
    def __init__(self, tool):
        super().__init__(tool)
        self.reference_hover_service = ReferenceListingHover(tool)

    def init(self):
        # The ReferenceHover is dependent on the CodeFormatService.
        pass

    def process_event(self, event):
        if isinstance(event, ProgramClosedPluginEvent):
            program_closed_event = event
            self.reference_hover_service.program_closed(program_closed_event.get_program())

    def dispose(self):
        self.reference_hover_service.dispose()

class ReferenceListingHover:
    def __init__(self, tool):
        pass

    def program_closed(self, program):
        pass

# Register the plugin with Ghidra
ghidra_app.register_plugin(ReferenceListingHoverPlugin)
```
Note that I've made some assumptions about how to translate certain parts of the code. For example:

* The `@PluginInfo` annotation is not directly translatable to Python, so I omitted it.
* The `registerServiceProvided` method and its corresponding imports are also not directly translatable, as they seem to be specific to Java's plugin architecture. In Python, you would typically register a service by creating an instance of the service class and assigning it to a variable or attribute.
* Similarly, I omitted the `CodeFormatService` import and any references to it in the code.

If you have more information about how Ghidra works with Python plugins, please let me know and I can try to provide a more accurate translation.