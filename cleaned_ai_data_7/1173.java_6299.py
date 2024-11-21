class IDebugHostSymbols:
    IID_IDEBUG_HOST_SYMBOLS = "854FD751-2E1C-Eb24-B525-6619CB97A588"

    VTIndices = {
        'CREATE_MODULE_SIGNATURE': 0,
        'CREATE_TYPE_SIGNATURE': 1,
        'CREATE_TYPE_SIGNATURE_FOR_MODULE_RANGE': 2,
        'ENUMERATE_MODULES': 3,
        'FIND_MODULE_BY_NAME': 4,
        'FIND_MODULE_BY_LOCATION': 5,
        'GET_MOST_DERIVED_OBJECT': 6
    }

    def create_module_signature(self, pwszModuleName: str, pwszMinVersion: str, pwszMaxVersion: str):
        pass

    def create_type_signature(self, signatureSpecification: str, module: object, typeSignature: object) -> int:
        return -1  # Return HRESULT value as an integer in Python

    def create_type_signature_for_module_range(
            self,
            signatureSpecification: str,
            moduleName: str,
            minVersion: str,
            maxVersion: str
    ) -> int:
        return -1  # Return HRESULT value as an integer in Python

    def enumerate_modules(self, context: object) -> tuple:
        pass

    def find_module_by_name(self, context: object, moduleName: str) -> object:
        pass

    def find_module_by_location(
            self,
            context: object,
            moduleLocation: object
    ) -> object:
        pass

    def get_most_derived_object(
            self,
            pContext: object,
            location: object,
            objectType: object,
            derivedLocation: tuple,
            derivedType: object
    ):
        pass
