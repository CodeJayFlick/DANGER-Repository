class TargetObjectSchemaInfo:
    def __init__(self):
        self.name = "Location"
        self.elements = [{}]
        self.attributes = [
            {"name": "Method", "type": str, "required": True, "fixed": True},
            {"name": "Line", "type": int, "required": True, "fixed": True},
            {"name": "Index", "type": int, "required": True, "fixed": True},
            {"name": "Address", "type": str, "required": True, "fixed": True}
        ]

class JdiModelTargetLocation:
    def __init__(self):
        self.location = None
        self.declaring_type = None
        self.address = None

    @staticmethod
    def get_unique_id(obj):
        return f"{obj}:{obj.code_index()}"

    def init(self, parent, location, is_element=False):
        super().__init__()
        self.location = location
        impl.register_method(location.method())
        self.address = self.get_address()
        change_attributes({}, {"Method": location.method().name(), "Line": location.line_number(),
                                "Index": location.code_index(), "Address": f"{self.address.offset}"}, "Initialized")

    def request_attributes(self, refresh=False):
        if not self.declaring_type:
            self.declaring_type = getInstance(location.declaring_type())
        change_attributes({}, {"Declaring Type": self.declaring_type}, "Initialized")
        try:
            source_name = location.source_name()
            source_path = location.source_path()
            change_attributes({}, {"Source Name": source_name, "Source Path": source_path}, "Initialized")
        except AbsentInformationException as e:
            pass
        return CompletableFuture.completed_future(None)

    def __init__(self):
        self.location = None

    @staticmethod
    def get_display(self):
        if not self.location:
            return super().get_display()
        return f"{location}:{Long.toHexString(address.offset)}"

    def get_address(self, impl=None):
        if address is not None:
            return address
        return getAddressFromLocation(impl, location)

    @staticmethod
    def get_address_from_location(impl, location):
        address_range = impl.get_address_range(location.method())
        if address_range is None:
            return impl.get_address_space("ram").get_address(-1)
        code_index = location.code_index()
        return address_range.min_address().add(code_index < 0 and 0 or code_index)

    def add_breakpoint(self):
        event_manager = self.location.virtual_machine().event_request_manager()
        request = event_manager.create_breakpoint_request(self.location)
        request.enable()
        return JdiBreakpointInfo(request)
