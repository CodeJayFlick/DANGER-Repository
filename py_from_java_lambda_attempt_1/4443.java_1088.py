Here is the translation of the Java code into Python:

```Python
import ghidra_app as app
from ghidra_framework import *
from ghidra_program_model_address import Address
from ghidra_program_model_listing import Program
from ghidra_resources import ResourceManager


class PropertyManagerPlugin:
    def __init__(self, tool):
        self.tool = tool
        self.property_view_provider = None

    def init(self):
        self.marker_service = app.get_service(MarkerService)
        self.update_timer = Timer(500)

    def domain_object_changed(self, ev):
        if not self.property_view_provider or not self.property_view_provider.is_visible():
            return

        affected_by_change = False
        for record in ev.records:
            event_type = record.event_type
            if (event_type == DomainObject.DO_OBJECT_RESTORED or 
                event_type == ChangeManager.DOCR_MEMORY_BLOCK_MOVED or 
                event_type == ChangeManager.DOCR_MEMORY_BLOCK_REMOVED or 
                event_type == ChangeManager.DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED):
                affected_by_change = True
                break

            if not isinstance(record, CodeUnitPropertyChangeRecord):
                continue

            pcr = record
            addr = pcr.address
            if addr:
                if self.current_selection and addr in self.current_selection:
                    affected_by_change = True
                    break
            else:
                start_addr = pcr.start_address
                end_addr = pcr.end_address
                if start_addr and end_addr and self.current_selection.intersects(start_addr, end_addr):
                    affected_by_change = True
                    break

        if affected_by_change:
            self.update_timer.restart()

    def program_activated(self, program):
        program.add_listener(self)
        self.property_view_provider.program_activated(program)

    def program_deactivated(self, program):
        self.dispose_search_marks(program)
        if program:
            program.remove_listener(self)
        self.property_view_provider.program_deactivated()

    def selection_changed(self, sel):
        if self.property_view_provider and self.property_view_provider.is_visible():
            self.update_timer.restart()

    def get_search_marks(self):
        if not self.search_marks or not self.current_program:
            return

        self.search_marks = self.marker_service.create_point_marker(
            PROPERTY_MARKER_NAME,
            "Locations where properties are set",
            self.current_program,
            MarkerService.PROPERTY_PRIORITY,
            True, True, False, Color.pink, prop_icon
        )

    def dispose_search_marks(self):
        if not self.search_marks or not self.current_program:
            return

        self.marker_service.remove_marker(self.search_marks, self.current_program)
        self.search_marks = None

    def clear_search_marks(self):
        if self.search_marks:
            self.search_marks.clear_all()

    def __del__(self):
        super().dispose()
        self.dispose_search_marks()
        if self.current_program:
            self.current_program.remove_listener(self)

        if self.property_view_provider:
            self.property_view_provider.dispose()
            self.property_view_provider = None

    @property
    def property_view_provider(self):
        return self.property_view_provider

    @property
    def current_selection(self):
        pass  # Replace with your implementation


# Usage example:

tool = app.get_tool()  # Get the Ghidra tool instance
plugin = PropertyManagerPlugin(tool)  # Create an instance of the plugin
```

Please note that this translation is not a direct conversion from Java to Python, but rather an interpretation based on my understanding of the code. The original Java code may have been written with specific requirements or constraints in mind, which are not necessarily applicable to the Python version.

In particular:

*   In Python, we don't need explicit `init` and `dispose` methods like in Java.
*   We use properties (`@property`) instead of getter/setter methods for attributes that should be accessed as read-only or write-only.
*   The `Timer` class is not a built-in Python type. You might want to consider using the `threading.Timer` module from the standard library, which provides similar functionality.

This code may require additional modifications and testing before it can be used in your specific context.