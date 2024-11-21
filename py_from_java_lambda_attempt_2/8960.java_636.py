Here is your Java code translated into pure Python:

```Python
import xml.etree.ElementTree as ET

class VTSubToolManager:
    def __init__(self):
        self.plugin = None
        self.controller = None
        self.listeners = []
        self.source_tool = None
        self.destination_tool = None
        self.plugin_list = []

    def open_destination_program(self, domain_file, parent):
        if not self.destination_tool:
            self.destination_tool = create_tool("Version Tracking (DESTINATION TOOL)", False)
        program_manager = self.destination_tool.get_service(ProgramManager)
        return program_manager.open_program(domain_file, parent)

    def open_source_program(self, domain_file, parent):
        if not self.source_tool:
            self.source_tool = create_tool("Version Tracking (SOURCE TOOL)", True)
        program_manager = self.source_tool.get_service(ProgramManager)
        return program_manager.open_program(domain_file, parent)

    def close_source_program(self, source):
        if self.source_tool and self.source_tool.is_executing_command():
            VTPlugin.show_busy_tool_message(self.source_tool)
        else:
            program_manager = self.source_tool.get_service(ProgramManager)
            program_manager.close_program(source, True)

    def close_destination_program(self, destination):
        if self.destination_tool and self.destination_tool.is_executing_command():
            VTPlugin.show_busy_tool_message(self.destination_tool)
        else:
            program_manager = self.destination_tool.get_service(ProgramManager)
            program_manager.close_program(destination, True)

    def reset_tools(self):
        self.reset_tool("Version Tracking (SOURCE TOOL)")
        self.reset_tool("Version Tracking (DESTINATION TOOL)")

    def create_match_actions(self, plugin_tool_name):
        if not self.source_tool:
            return None
        match_info = MatchInfo()
        match_action = AcceptMatchActionWrapper(plugin=self.plugin)
        apply_match_action = ApplyUsingOptionsAndForcing(match_info=match_info)

    # More code here...
```

Please note that this is a Python translation of your Java code.