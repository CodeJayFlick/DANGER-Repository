Here is a translation of the provided Java code into equivalent Python:

```Python
class TranslateAction:
    def __init__(self, owner: str, service):
        self.service = service
        super().__init__("Translate with " + service.translation_service_name(), owner)

    @property
    def help_location(self) -> HelpLocation | None:
        return self.service.help_location

    @help_location.setter
    def help_location(self, value: HelpLocation | None):
        if value is not None:
            super().set_help_location(value)
        else:
            super().unset_help_location()

class MenuData:
    def __init__(self, items: list[str], group: str = "Group"):
        self.items = items
        self.group = group

def get_code_viewer_menu_data(service):
    return MenuData(["Data", "Translate", service.translation_service_name()], "GROUP")

def get_data_list_menu_data(service):
    return MenuData(["Translate", service.translation_service_name()], "GROUP")

class Program:
    def __init__(self, program: str):
        self.program = program

class ProgramLocation:
    pass  # No equivalent in Python. Assuming it's a class that doesn't need translation.

def translate_action_performed(program: Program, data_locations: list[ProgramLocation]):
    service.translate(program, data_locations)
```

Note:

- In the provided Java code, there are classes like `AbstractTranslateAction`, `StringTranslationService`, and others which have not been translated as they do not provide any specific functionality that can be directly converted into Python. The translation is based on the available information.
- Some methods in the original Java code (like `getCodeViewerMenuData` and `getDataListMenuData`) are static, but their equivalent functions (`get_code_viewer_menu_data` and `get_data_list_menu_data`) in this translated Python code do not have a specific class. They can be used as standalone functions.
- The translation of the original Java code into Python does not include any GUI components like docking actions or menus which were present in the original code.