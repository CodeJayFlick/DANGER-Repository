Here is the translation of the Java code to Python:

```Python
class CreateGhidraScriptWizard:
    def __init__(self):
        self.workbench = None
        self.script_page = None

    def init(self, workbench: object, selection: list) -> None:
        if isinstance(selection[0], dict):  # Assuming IPackageFragmentRoot is a dictionary in Python
            selected_package_fragment_root = selection[0]
        else:
            raise ValueError("Invalid selection")
        
        self.workbench = workbench
        self.script_page = CreateGhidraScriptWizardPage(selected_package_fragment_root)

    def add_pages(self) -> None:
        self.add_page(self.script_page)


class CreateGhidraScriptWizardPage:
    def __init__(self, selected_package_fragment_root: dict):
        pass  # Assuming IPackageFragmentRoot is a dictionary in Python

    def get_script_folder(self) -> object:
        return None  # Replace with actual implementation

    def get_script_name(self) -> str:
        return ""

    def get_script_author(self) -> str:
        return ""

    def get_script_category(self) -> str:
        return ""

    def get_script_description(self) -> list[str]:
        return []


class GhidraScriptUtils:
    @staticmethod
    def create_ghidra_script(script_folder: object, script_name: str, author: str, category: str, description: list[str], monitor=None):
        pass  # Replace with actual implementation


def perform_finish(self) -> bool:
    try:
        if self.script_page.get_script_folder() is not None and \
           self.script_page.get_script_name() != "" and \
           self.script_page.get_script_author() != "":
            script_file = GhidraScriptUtils.create_ghidra_script(
                self.script_page.get_script_folder(), 
                self.script_page.get_script_name(),
                self.script_page.get_script_author(),
                self.script_page.get_script_category(),
                self.script_page.get_script_description()
            )
            if script_file is not None:
                # Replace with actual implementation for EclipseMessageUtils.display_in_editor
                pass

    except (IOException, CoreException) as e:
        raise InvocationTargetException(e)

    return True


def main():
    wizard = CreateGhidraScriptWizard()

if __name__ == "__main__":
    main()
```

Please note that the translation is not a direct conversion from Java to Python. The code has been adapted and modified according to Python's syntax, semantics, and best practices.