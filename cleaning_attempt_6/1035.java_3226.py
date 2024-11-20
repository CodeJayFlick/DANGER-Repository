import ctypes

class DebugHostExtensabilityImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # No direct equivalent in Python for OpaqueCleanable
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def create_function_alias(self, alias_name: str, function_object) -> None:
        p_function_object = ctypes.c_void_p(function_object)
        result = self.jna_data.create_function_alias(alias_name.encode('utf-8'), p_function_object)
        if not isinstance(result, int):
            raise ValueError(f"Error creating function alias. RC={result}")

    def destroy_function_alias(self, alias_name: str) -> None:
        result = self.jna_data.destroy_function_alias(alias_name.encode('utf-8'))
        if not isinstance(result, int):
            raise ValueError(f"Error destroying function alias. RC={result}")
