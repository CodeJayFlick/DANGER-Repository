Here is the translation of the given Java code into Python:

```Python
class Template:
    def __init__(self):
        self.function_1_action = None
        self.function_2_action = None
        self.function_3_action = None

    def setup_actions(self, tool):
        action = DockingAction("Function 1 Code", "Template")
        action.actionPerformed = lambda e: self.Function_1()
        action.is_add_to_popup = lambda context: isinstance(context.get_context_object(), ListingActionContext)
        if not self.get_program():
            action.set_enabled(False)
        tool.add_action(action)
        self.function_1_action = action

        action = DockingAction("Function 2 Code", "Template")
        action.actionPerformed = lambda e: self.Function_2()
        action.is_valid_context = lambda context: isinstance(context, ListingActionContext)
        if not self.get_program():
            action.set_enabled(False)
        tool.add_action(action)
        self.function_2_action = action

        action = DockingAction("Function 3 Code", "Template")
        action.actionPerformed = lambda e: self.Function_3()
        action.is_valid_context = lambda context: isinstance(context, ListingActionContext)
        if not self.get_program():
            action.set_enabled(False)
        tool.add_action(action)
        self.function_3_action = action

    def get_program(self):
        pm = ProgramManager(tool=tool)
        return pm.current_program() if pm else None

class DockingAction:
    def __init__(self, name, plugin_name):
        self.name = name
        self.plugin_name = plugin_name
        self.action_performed = None
        self.is_add_to_popup = None
        self.set_enabled(True)

    def set_menu_bar_data(self, menu_data):
        pass

class ProgramManager:
    def __init__(self, tool=None):
        self.tool = tool
        self.current_program = None

    def current_program(self):
        return self.current_program if self else None

def process_event(event):
    if isinstance(event, ProgramActivatedPluginEvent):
        p = event.active_program()
        function_1_action.set_enabled(p is not None)
        function_2_action.set_enabled(p is not None)
        function_3_action.set_enabled(p is not None)

# Usage
tool = ...  # Initialize your tool here.
template = Template()
template.setup_actions(tool)
process_event(event)  # Process the event as needed.
```

Please note that Python does not have direct equivalent of Java's `abstract class` and `interface`. The concept of abstract classes is replaced by using a regular class with an empty body.