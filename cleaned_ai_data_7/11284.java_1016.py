class ToolServicesImpl:
    def __init__(self, tool_chest: 'ToolChest', tool_manager: 'ToolManager'):
        self.tool_chest = tool_chest
        self.tool_manager = tool_manager
        self.listeners = []
        self.content_handlers = set()

    def dispose(self):
        if hasattr(self, 'tool_chest_listener'):
            self.tool_chest.remove_tool_chest_listener(self.tool_chest_listener)

    @property
    def tool_chest_listener(self):
        return None

    def close_tool(self, tool: 'PluginTool') -> None:
        self.tool_manager.close_tool(tool)

    def export_tool(self, tool: 'ToolTemplate', file_name=None) -> str:
        if not file_name:
            location = self.choose_file(tool)
            if not location:
                return location
        try:
            with open(location, 'wb') as f:
                doc = Document(to_xml(tool.save_to_xml()))
                xmlout = GenericXMLOutputter()
                xmlout.output(doc, f)
        except Exception as e:
            print(f"Error: {e}")
        return location

    def choose_file(self, tool) -> str | None:
        file_chooser = GhidraFileChooser(None)

        while True:
            export_file = file_chooser.get_selected_file()
            if not export_file:
                return None
            Preferences.set_property('LAST_TOOL_EXPORT_DIRECTORY', export_file.parent)
            if not export_file.name.endswith(ToolUtils.TOOL_EXTENSION):
                export_file = File(f"{export_file.path}{ToolUtils.TOOL_EXTENSION}")
            if export_file.exists():
                result = OptionDialog.show_option_dialog(None, "Overwrite?", f"Overwrite existing file: '{export_file.name}'?", 'Overwrite', QuestionMessage)
                if result != OptionDialog.OPTION_ONE:
                    return None
            return str(export_file)

    def get_tool_chest(self) -> 'ToolChest':
        return self.tool_chest

    @property
    def tool_manager(self):
        return self._tool_manager

    @tool_manager.setter
    def tool_manager(self, value: 'ToolManager'):
        self._tool_manager = value

    def display_similar_tool(self, tool: 'PluginTool', domain_file: 'DomainFile', event: 'PluginEvent') -> None:
        similar_tools = [t for t in get_same_named_running_tools(tool) if issubclass(type(t), PluginTool)]
        matching_tool = find_tool_using_file(similar_tools, domain_file)
        if matching_tool:
            matching_tool.to_front()
        else:
            workspace = self.tool_manager.get_active_workspace()
            matching_tool = workspace.run_tool(ToolTemplate(True))
            matching_tool.set_visible(True)
            matching_tool.accept_domain_files([domain_file])
        # Fire the indicated event in the tool.
        matching_tool.fire_plugin_event(event)

    def launch_default_tool(self, domain_file: 'DomainFile') -> 'PluginTool':
        template = self.get_default_tool_template(domain_file)
        if not template:
            return None
        workspace = self.tool_manager.get_active_workspace()
        tool = workspace.run_tool(template)
        tool.set_visible(True)
        if domain_file:
            tool.accept_domain_files([domain_file])
        return tool

    def launch_tool(self, tool_name: str, domain_file: 'DomainFile') -> 'PluginTool':
        template = self.find_tool_chest_tool_template(tool_name)
        if not template:
            return None
        workspace = self.tool_manager.get_active_workspace()
        tool = workspace.run_tool(template)
        tool.set_visible(True)
        if domain_file:
            tool.accept_domain_files([domain_file])
        return tool

    def set_content_type_tool_associations(self, content_handlers: list) -> None:
        for info in content_handlers:
            handler = info.get_handler()
            preference_key = self.get_preference_key(handler.content_type())
            if not info.is_default():
                template = info.current_template
                Preferences.set_property(preference_key, template.name)
            else:
                Preferences.remove_property(preference_key)

    def get_content_type_tool_associations(self) -> list:
        set_ = set()
        for handler in self.get_content_handlers():
            set_.add(ToolAssociationInfo(handler))
        return [info for info in set_]

    @property
    def content_handlers(self):
        if not hasattr(self, '_content_handlers'):
            self._content_handlers = []
        return self._content_handlers

    def get_preference_key(self, content_type: str) -> str:
        return f"ToolAssociation:{SEPARATOR}{content_type}"

    # ... and so on.
