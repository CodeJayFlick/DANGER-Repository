# No license information or copyright notices are included in this Python version.

class GhidraRootPreferenceInitializer:
    def initialize_default_preferences(self):
        store = Activator().get_preference_store()
        store.set_default('GHIDRA_REQUESTED_OPEN_PORT_CONSENT', False)
