class WrapIDataModelScriptManager:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def get_default_name_binder(self) -> int:
        # Assuming _invokeHR and VTIndices are defined elsewhere in the codebase
        return _invokeHR(VTIndices.GET_DEFAULT_NAME_BINDER)

    def register_script_provider(self, provider: object) -> int:
        return _invokeHR(VTIndices.REGISTER_SCRIPT_PROVIDER, provider)

    def unregister_script_provider(self, provider: object) -> int:
        return _invokeHR(VTIndices.UNREGISTER_SCRIPT_PROVIDER, self.pv_instance, provider)

    def find_provider_for_script_type(self, script_type: str, provider: object) -> int:
        return _invokeHR(VTIndices.FIND_PROVIDER_FOR_SCRIPT_TYPE, self.pv_instance, script_type, provider)

    def find_provider_for_script_extension(self, script_extension: str, provider: object) -> int:
        return _invokeHR(VTIndices.FIND_PROVIDER_FOR_SCRIPT_EXTENSION, self.pv_instance, script_extension, provider)

    def enumerate_script_providers(self) -> int:
        return _invokeHR(VTIndices.ENUMERATE_SCRIPT_PROVIDERS, self.pv_instance)
