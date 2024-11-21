class HostDataModelAccessImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # equivalent to OpaqueCleanable in Java
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def get_jna_data(self):
        return self.jna_data

    def get_data_model(self):
        manager_ptr = PointerByReference()
        host_ptr = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_data_model(manager_ptr, host_ptr))

        wrap0 = WrapIDataModelManager1(manager_ptr.value)
        try:
            self.manager = DataModelManagerInternal.try_preferred_interfaces(wrap0.query_interface())
        finally:
            wrap0.release()

        wrap1 = WrapIDebugHost(host_ptr.value)
        try:
            self.host = DebugHostInternal.try_preferred_interfaces(wrap1.query_interface())
        finally:
            wrap1.release()

    def get_manager(self):
        return self.manager

    def get_host(self):
        return self.host

    def get_client(self):
        return self.debug_client

    def set_client(self, debug_client):
        self.debug_client = debug_client
