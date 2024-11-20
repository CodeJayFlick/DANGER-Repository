class WorkspaceImpl:
    def __init__(self, name: str, tool_manager):
        self.name = name
        self.tool_manager = tool_manager
        self.running_tools = set()
        self.is_active = False

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        self._name = value

    def get_tools(self) -> list:
        tools = []
        for tool in self.running_tools:
            tools.append(tool)
        return tools

    def create_tool(self) -> 'PluginTool':
        empty_tool = self.tool_manager.create_empty_tool()
        self.running_tools.add(empty_tool)
        empty_tool.setVisible(True)
        self.tool_manager.set_workspace_changed(self)
        self.tool_manager.fire_tool_added_event(self, empty_tool)
        return empty_tool

    def run_tool(self, template: str) -> 'PluginTool':
        tool = self.tool_manager.get_tool(self, template)
        if tool is not None:
            tool.setVisible(True)
            if isinstance(tool, GhidraTool):
                gtool = cast(GhidraTool, tool)
                gtool.check_for_new_extensions()
            self.running_tools.add(tool)
            self.tool_manager.set_workspace_changed(self)
            self.tool_manager.fire_tool_added_event(self, tool)
        return tool

    def set_name(self, new_name: str) -> None:
        if not isinstance(new_name, str):
            raise TypeError("Name must be a string")
        try:
            self.tool_manager.set_workspace_name(self, new_name)
        except DuplicateNameException as e:
            print(f"Error setting name: {e}")
        finally:
            self.name = new_name
            self.tool_manager.set_workspace_changed(self)

    def set_active(self) -> None:
        if not isinstance(self.is_active, bool):
            raise TypeError("Active must be a boolean")
        try:
            self.tool_manager.set_active_workspace(self)
            self.setVisible(True)
        except Exception as e:
            print(f"Error setting active: {e}")

    def __str__(self) -> str:
        return f"{self.name}"

    def save_to_xml(self) -> Element:
        root = Element("WORKSPACE")
        root.set_attribute("NAME", self.name)
        root.set_attribute("ACTIVE", "true" if self.is_active else "false")

        for tool in self.running_tools:
            elem = Element("RUNNING_TOOL")
            elem.set_attribute("TOOL_NAME", tool.get_tool_name())
            elem.add_content(tool.save_windowing_data_to_xml())
            elem.add_content(tool.save_data_state_to_xml(True))
            root.add_content(elem)

        return root

    def restore_from_xml(self, root: Element) -> None:
        if "NAME" in root.attributes and isinstance(root.attributes["NAME"], str):
            self.name = root.attributes["NAME"]
        elif "ACTIVE" in root.attributes and isinstance(root.attributes["ACTIVE"], str):
            self.is_active = root.attributes["ACTIVE"] == "true"

        default_tool = os.environ.get("ghidra.defaulttool")
        if default_tool is not None:
            tool = self.tool_manager.get_tool(default_tool)
            self.running_tools.add(tool)
            self.tool_manager.fire_tool_added_event(self, tool)

        for elem in root.children["RUNNING_TOOL"]:
            tool_name = elem.attributes[ToolTemplate.TOOL_NAME_XML_NAME]
            if tool_name is not None and isinstance(tool_name, str):
                tool = self.tool_manager.get_tool(tool_name)
                if tool is not None:
                    tool.setVisible(self.is_active)

                    if isinstance(tool, GhidraTool):
                        gtool = cast(GhidraTool, tool)
                        gtool.check_for_new_extensions()

                    had_changes = tool.has_config_changed()
                    tool.restore_windowing_data_from_xml(elem)
                    elem_tool_data_elem = elem.child("DATA_STATE")
                    tool.restore_data_state_from_xml(elem_tool_data_elem)

                    if had_changes:
                        # restore the dirty state, which is cleared by the restoreDataState call
                        tool.set_config_changed(True)

                    self.running_tools.add(tool)
                    self.tool_manager.fire_tool_added_event(self, tool)

    def set_visible(self, state: bool) -> None:
        self.is_active = state

        for tool in self.get_tools():
            tool.setVisible(state)

    def close_running_tool(self, tool: 'PluginTool') -> None:
        if isinstance(tool, PluginTool):
            try:
                # tool is already closed via the call that got us here, so just clean up
                self.running_tools.remove(tool)
            except ValueError as e:
                print(f"Error closing running tool: {e}")

            # alert the tool manager that we changed
            self.tool_manager.set_workspace_changed(self)

        try:
            if isinstance(tool, GhidraTool):
                gtool = cast(GhidraTool, tool)
                gtool.exit()
        except Exception as e:
            print(f"Error closing running tool: {e}")

    def close(self) -> None:
        for tool in self.running_tools.copy():
            try:
                if isinstance(tool, GhidraTool):
                    gtool = cast(GhidraTool, tool)
                    gtool.exit()
                else:
                    tool.exit()
            except Exception as e:
                print(f"Error closing running tool: {e}")

        self.running_tools.clear()

    def __del__(self) -> None:
        if hasattr(self, "running_tools"):
            for tool in self.running_tools.copy():
                try:
                    if isinstance(tool, GhidraTool):
                        gtool = cast(GhidraTool, tool)
                        gtool.exit()
                    else:
                        tool.exit()
                except Exception as e:
                    print(f"Error closing running tool: {e}")
