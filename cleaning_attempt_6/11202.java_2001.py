class ToolChest:
    def __init__(self):
        self.tool_templates = []
        self.listeners = []

    def get_tool_template(self, tool_name: str) -> 'ToolTemplate' | None:
        for template in self.tool_templates:
            if template.name == tool_name:
                return template
        return None

    def get_tool_templates(self) -> list['ToolTemplate']:
        return self.tool_templates[:]

    def add_tool_chest_change_listener(self, listener: callable):
        self.listeners.append(listener)

    def remove_tool_chest_change_listener(self, listener: callable):
        if listener in self.listeners:
            self.listeners.remove(listener)

    def add_tool_template(self, template: 'ToolTemplate') -> bool:
        for i, existing_template in enumerate(self.tool_templates):
            if existing_template.name == template.name:
                new_name = f"{template.name}_{i+1}"
                template.name = new_name
                return True
        self.tool_templates.append(template)
        return True

    def remove(self, tool_name: str) -> bool:
        for i, template in enumerate(self.tool_templates):
            if template.name == tool_name:
                del self.tool_templates[i]
                return True
        return False

    @property
    def tool_count(self) -> int:
        return len(self.tool_templates)

    def replace_tool_template(self, template: 'ToolTemplate') -> bool:
        for i, existing_template in enumerate(self.tool_templates):
            if existing_template.name == template.name:
                self.remove(existing_template.name)
                return self.add_tool_template(template)
        return False
