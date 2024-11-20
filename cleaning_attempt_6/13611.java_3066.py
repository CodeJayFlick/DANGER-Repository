class GhidraScriptEditorPreferenceInitializer:
    def initialize_default_preferences(self):
        store = Activator().get_preference_store()
        store.set_default('GHIDRA_SCRIPT_EDITOR_ENABLED', False)
        store.set_default('GHIDRA_SCRIPT_EDITOR_PORT_NUMBER', '12321')

# Note: Python does not have direct equivalent of Java's AbstractPreferenceInitializer and IPreferenceStore.
