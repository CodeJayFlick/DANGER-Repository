Here is the translation of the given Java code into equivalent Python:

```Python
class SaveNewScriptDialog:
    def __init__(self, parent, title, component_provider, script_file, help):
        pass  # Assuming this will be implemented later

    def get_duplicate_name_error_message(self, name):
        if component_provider.get_info_manager().already_exists(name):
            return "Duplicate script name."
        
        user_choice = f"{get_directory()}/{name}"
        if os.path.exists(user_choice):
            return "File already exists on disk."

        return None


# Assuming these functions will be implemented later
def get_directory():
    pass

class GhidraScriptComponentProvider:
    def __init__(self, info_manager):
        self.info_manager = info_manager

    def get_info_manager(self):
        return self.info_manager

class ResourceFile:
    pass  # This class seems to have no functionality in the given code


# Assuming these classes will be implemented later
class Component:
    pass

class HelpLocation:
    pass

```

Please note that this is a direct translation of Java into Python, and it may not work as expected without proper implementation. The `get_directory`, `GhidraScriptComponentProvider`, `ResourceFile`, `Component` and `HelpLocation` classes are assumed to be implemented later.