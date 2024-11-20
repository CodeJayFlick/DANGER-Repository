Here is the equivalent Python code:

```Python
class GhidraSymbolLookupPreferenceInitializer:
    def initialize_default_preferences(self):
        store = Activator().get_preference_store()
        store.set_default('GHIDRA_SYMBOL_LOOKUP_ENABLED', False)
        store.set_default('GHIDRA_SYMBOL_LOOKUP_PROJECT_NAME', '')
        store.set_default('GHIDRA_SYMBOL_LOOKUP_PORT_NUMBER', '12322')

# You can use this class as follows:
initializer = GhidraSymbolLookupPreferenceInitializer()
initializer.initialize_default_preferences()
```

Please note that Python does not have direct equivalent of Java's package and import statements. Also, Activator() is assumed to be a function or an object with get_preference_store method in the given code.