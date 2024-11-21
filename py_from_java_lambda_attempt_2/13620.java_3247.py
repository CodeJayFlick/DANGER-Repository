Here is the equivalent Python code:

```Python
class GhidraSymbolLookupPreferences:
    GHIDRA_SYMBOL_LOOKUP_ENABLED = "ghidradev.symbolLookupEnabled"
    GHIDRA_SYMBOL_LOOKUP_PROJECT_NAME = "ghidradev.symbolLookupProjectName"
    GHIDRA_SYMBOL_LOOKUP_PORT_NUMBER = "ghidradev.symbolLookupPortNumber"

    def is_symbol_lookup_enabled(self):
        prefs = Activator().get_preference_store()
        return prefs.getboolean(GHIDRA_SYMBOL_LOOKUP_ENABLED)

    def set_symbol_lookup_enabled(self, enabled):
        prefs = Activator().get_preference_store()
        prefs.setvalue(GHIDRA_SYMBOL_LOOKUP_ENABLED, enabled)

    def get_symbol_lookup_project_name(self):
        prefs = Activator().get_preference_store()
        name = prefs.getstring(GHIDRA_SYMBOL_LOOKUP_PROJECT_NAME)
        if not name:
            return None
        return name

    def get_symbol_lookup_port(self):
        prefs = Activator().get_preference_store()
        try:
            port = int(prefs.getstring(GHIDRA_SYMBOL_LOOKUP_PORT_NUMBER))
            return port
        except ValueError:
            return -1


# Example usage:

prefs = GhidraSymbolLookupPreferences()

if prefs.is_symbol_lookup_enabled():
    print("Symbol lookup is enabled")
else:
    print("Symbol lookup is disabled")

port = prefs.get_symbol_lookup_port()
print(f"Port: {port}")

project_name = prefs.get_symbol_lookup_project_name()
print(f"Project name: {project_name}")
```

Please note that Python does not have direct equivalent of Java's `IPreferenceStore` and other classes. The above code is a simple translation of the given Java code to Python, assuming some basic knowledge of Python programming.