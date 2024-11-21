class CreateFunctionDefinitionCmd:
    def __init__(self, entry, service_provider):
        self.entry = entry
        self.service_provider = service_provider
        self.status_msg = ""

    def get_name(self):
        return "Create Function Definition"

    def apply_to(self, obj):
        program = Program(obj)
        listing = program.get_listing()
        dtm = listing.get_data_type_manager()
        func = listing.get_function_at(entry)

        if not func:
            return False

        try:
            sig = func.get_signature(True)
        except Exception as e:
            self.status_msg = str(e)
            return False

        function_def = FunctionDefinitionDataType(sig)
        new_type = dtm.resolve(function_def, None)

        service = self.service_provider.get_service(DataTypeManagerService)
        if service:
            service.set_data_type_selected(new_type)

        return True

    def get_status_msg(self):
        return self.status_msg


class Program:
    def __init__(self, obj):
        pass  # Assuming this is a wrapper for the Java program object

class FunctionDefinitionDataType:
    def __init__(self, sig):
        pass  # Assuming this is a Python equivalent of the Java data type
