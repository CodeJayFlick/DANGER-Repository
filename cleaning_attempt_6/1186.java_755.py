class WrapIDebugHostField:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        # No direct equivalent in Python for super() call.
        pass

    def get_location_kind(self):
        return 0  # Assuming HRESULT is always 0 (success)

    def get_offset(self):
        return 0  # Assuming ULONGLONGByReference is always 0 (success)

    def get_location(self):
        return {}  # Assuming LOCATION.ByNameReference returns a dictionary

    def get_value(self):
        return None  # Assuming VARIANT.ByReference returns None
