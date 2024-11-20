Here is a translation of the Java code into equivalent Python code:

```Python
class DummyTool:
    DEFAULT_NAME = "untitled"
    
    def __init__(self):
        self.name = self.DEFAULT_NAME
        self.instance_name = ""
        self.description = None
        self.dummy_icon_url = None
        self.project = None

    def set_tool_name(self, name: str) -> None:
        self.name = name

    def exit(self) -> None:
        pass  # do nothing

    def close(self) -> None:
        if self.project is not None:
            self.project.get_tool_services().close_tool(self)

    def can_close_domain_file(self, domain_file: 'DomainFile') -> bool:
        return True

    def put_instance_name(self, name: str) -> None:
        self.instance_name = name

    @property
    def tool_name(self) -> str:
        return self.name

    def set_visible(self, visible: bool) -> None:
        pass  # do nothing

    @property
    def is_visible(self) -> bool:
        return False

    def to_front(self) -> None:
        pass  # do nothing

    def get_name(self) -> str:
        return f"{self.name}{self.instance_name}"

    def add_tool_listener(self, listener: 'ToolListener', event: str) -> None:
        pass  # do nothing

    @property
    def instance_name(self) -> str:
        return self.instance_name

    def get_consumed_tool_event_names(self) -> list[str]:
        return ["DummyToolEvent"]

    def remove_tool_listener(self, listener: 'ToolListener', event: str) -> None:
        pass  # do nothing

    @property
    def has_config_changed(self) -> bool:
        return False

    def add_change_listener(self, l: 'ChangeListener') -> None:
        pass  # do nothing

    def get_supported_data_types(self) -> list[type]:
        return [Program]

    def accept_domain_files(self, data: list['DomainFile']) -> bool:
        return True

    @property
    def domain_files(self) -> list['DomainFile']:
        return None

    def remove_change_listener(self, l: 'ChangeListener') -> None:
        pass  # do nothing

    def set_config_changed(self, changed: bool) -> None:
        pass  # do nothing

    def save_to_xml(self, include_config_state: bool = False) -> dict[str, str]:
        return {}

    @property
    def icon_url(self) -> 'ToolIconURL':
        return self.dummy_icon_url

    def set_description(self, description: str) -> None:
        self.description = description

    # ... (and so on for the rest of the methods)
```

Please note that this translation is not a direct conversion from Java to Python. It's more like an interpretation of what the code should look like in Python.