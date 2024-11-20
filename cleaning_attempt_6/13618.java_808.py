class GhidraSymbolLookupPreferenceInitializer:
    def initialize_default_preferences(self):
        store = Activator().get_preference_store()
        store.set_default('GHIDRA_SYMBOL_LOOKUP_ENABLED', False)
        store.set_default('GHIDRA_SYMBOL_LOOKUP_PROJECT_NAME', '')
        store.set_default('GHIDRA_SYMBOL_LOOKUP_PORT_NUMBER', '12322')

# You can use this class as follows:
initializer = GhidraSymbolLookupPreferenceInitializer()
initializer.initialize_default_preferences()
