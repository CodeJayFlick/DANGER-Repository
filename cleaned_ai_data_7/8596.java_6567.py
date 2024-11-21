class DisabledSymbolServer:
    DISABLED_PREFIX = "disabled://"

    @staticmethod
    def is_disabled_symbol_server_location(loc):
        return loc.startswith(DisabledSymbolServer.DISABLED_PREFIX)

    @classmethod
    def create_instance(cls, location_string, context):
        delegate = context.get_symbol_server_instance_creator_registry().new_symbol_server(location_string[len(DisabledSymbolServer.DISABLED_PREFIX):], context)
        if delegate is not None:
            return DisabledSymbolServer(delegate)
        else:
            return None

    def __init__(self, delegate):
        self.delegate = delegate

    @property
    def symbol_server(self):
        return self.delegate

    def get_name(self):
        return f"{DisabledSymbolServer.DISABLED_PREFIX}{self.delegate.get_name()}"

    def get_descriptive_name(self):
        return f"Disabled - {self.delegate.get_descriptive_name()}"

    def is_valid(self, monitor=None):
        return self.delegate.is_valid(monitor)

    def exists(self, filename, monitor=None):
        return False

    def find(self, file_info, find_options, monitor=None):
        return []

    def get_file_stream(self, filename, monitor=None):
        try:
            return self.delegate.get_file_stream(filename, monitor)
        except (Exception):  # catch all exceptions
            pass

    def get_file_location(self, filename):
        return self.delegate.get_file_location(filename)

    def is_local(self):
        return self.delegate.is_local()

    def __str__(self):
        return f"DisabledSymbolServer: [{self.delegate.__str()}]"
