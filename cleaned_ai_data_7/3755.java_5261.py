import pyghidra

class DataDropOnBrowserHandler:
    ACCEPTABLE_FLAVORS = [pyghidra.datatype.DataTypeTransferable.local_data_type_flavor,
                           pyghidra.datatype.DataTypeTransferable.local_builtin_data_type_flavor]

    def __init__(self, plugin):
        self.plugin = plugin
        self.cur_service = None

    def get_priority(self):
        return 20

    def get_data_flavors(self):
        return self.ACCEPTABLE_FLAVORS

    def is_drop_ok(self, context_obj, evt):
        if not (evt.is_supported(pyghidra.datatype.DataTypeTransferable.local_data_type_flavor) or
                evt.is_supported(pyghidra.datatype.DataTypeTransferable.local_builtin_data_type_flavor)):
            return False

        if context_obj and isinstance(context_obj, pyghidra.app.context.ListingActionContext):
            pl = ListingActionContext(context_obj)
            services = self.plugin.get_tool().get_services(DataService)
            for service in services:
                if service.is_create_data_allowed(pl):
                    self.cur_service = service
                    return True

        return False

    def add(self, context_obj, data, flavor):
        if self.cur_service:
            dt = DataType(data)
            self.cur_service.create_data(dt, ListingActionContext(context_obj), True)

# Note: This code assumes you have the pyghidra library installed and imported.
