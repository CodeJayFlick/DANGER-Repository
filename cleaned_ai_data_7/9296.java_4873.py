class KeyBindingType:
    UNSUPPORTED = "UNSUPPORTED"
    INDIVIDUAL = "INDIVIDUAL"
    SHARED = "SHARED"

    def supports_key_bindings(self):
        return self != KeyBindingType.UNSUPPORTED

    def is_shared(self):
        return self == KeyBindingType.SHARED

    def is_managed(self):
        return self == KeyBindingType.INDIVIDUAL
