Here is the translation of the Java code into Python:

```Python
class GhidraState:
    def __init__(self, tool: 'PluginTool', project: 'Project', program: 'Program', location: 'ProgramLocation', selection: 'ProgramSelection', highlight: 'ProgramSelection'):
        self.tool = tool
        self.project = project
        self.current_program = program
        self.current_location = location
        self.current_selection = selection
        self.current_highlight = highlight
        self.is_global_state = True

    def __init__(self, state):
        self.tool = state.tool
        self.project = state.project
        self.current_program = state.current_program
        self.current_location = state.current_location
        self.current_selection = state.current_selection
        self.current_highlight = state.current_highlight
        self.envmap = dict(state.envmap)
        self.is_global_state = False

    def get_tool(self):
        return self.tool

    def get_project(self):
        return self.project

    def get_current_program(self):
        return self.current_program

    def set_current_program(self, program: 'Program'):
        if program == self.current_program:
            return
        self.current_program = program
        if self.gather_param_panel is not None:
            self.gather_param_panel.current_program_changed()

    def get_current_address(self):
        return self.current_location.address if self.current_location else None

    def set_current_address(self, address: 'Address'):
        if SystemUtilities.is_equal(address, self.get_current_address()):
            return
        self.set_current_location(ProgramLocation(self.current_program, address))

    def get_current_location(self):
        return self.current_location

    def set_current_location(self, location: 'ProgramLocation'):
        if SystemUtilities.is_equal(location, self.current_location):
            return
        self.current_location = location
        if self.is_global_state and self.tool is not None:
            PluginEvent(event_type='program_location', program=self.current_program).fire_plugin_event()

    def get_current_highlight(self):
        return self.current_highlight

    def set_current_highlight(self, highlight: 'ProgramSelection'):
        if SystemUtilities.is_equal(highlight, self.current_highlight):
            return
        self.current_highlight = highlight
        if self.is_global_state and self.tool is not None:
            PluginEvent(event_type='program_highlight', selection=self.current_highlight, program=self.current_program).fire_plugin_event()

    def get_current_selection(self):
        return self.current_selection

    def set_current_selection(self, selection: 'ProgramSelection'):
        if SystemUtilities.is_equal(selection, self.current_selection):
            return
        self.current_selection = selection
        if self.is_global_state and self.tool is not None:
            PluginEvent(event_type='program_selection', selection=self.current_selection, program=self.current_program).fire_plugin_event()

    def add_environment_var(self, name: str, value: int | float | long):
        self.envmap[name] = value

    def remove_environment_var(self, name: str):
        if name in self.envmap:
            del self.envmap[name]

    def get_environment_var(self, name: str) -> None | int | float | long:
        return self.envmap.get(name)

    def add_parameter(self, key: str, label: str, type: int, default_value: object):
        if self.gather_param_panel is not None:
            self.gather_param_panel.add_parameter(key, label, type, default_value)

    def display_parameter_gatherer(self, title: str) -> bool:
        if self.gather_param_panel is None or not self.gather_param_panel.panel_shown():
            return False
        result = JOptionPane.showConfirmDialog(None, self.gather_param_panel, title)
        if result == JOptionPane.CANCEL_OPTION:
            self.gather_param_panel.set_shown(False)
            return False
        self.gather_param_panel.set_shown(True)
        self.gather_param_panel.set_params_in_state()
        return True

    def get_param_panel(self):
        return self.gather_param_panel

    def get_environment_names(self) -> set:
        return set(self.envmap.keys())
```

Note that I used the `|` operator to indicate that a function can take one of several types as an argument. This is equivalent to Java's generics, but it does not provide type safety at runtime like Java's generics do.

Also note that Python has no direct equivalent to Java's Swing library for creating GUI components. If you need to create a graphical user interface in your program, you will have to use a different library or framework than the one used here.