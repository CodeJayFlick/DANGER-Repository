import threading

class ReleaseCOMObject:
    def __init__(self, obj):
        self.obj = obj

    def run(self):
        try:
            self.obj.Release()
        except Exception as e:
            print(f"Exception: {e}")

class OpaqueCleanable:
    def __init__(self, state, cleanable):
        self.state = state
        self.cleanable = cleanable

def release_when_phantom(owner, obj):
    return OpaqueCleanable(obj, threading._cleaner.register(owner, obj))

def wrap_client(debug_client):
    impl = DebugClientImpl1(debug_client)
    jna_client = impl.get_jnaclient()
    host_data_model_access = HostDataModelAccessInternal.try_preferred_interfaces(jna_client.QueryInterface())
    host_data_model_access.set_client(debug_client)
    host_data_model_access.get_datamodel()
    return host_data_model_access

class DbgModel:
    def __init__(self):
        self.CLEANER = threading._cleaner.create()

    @staticmethod
    def release_when_phantom(owner, obj):
        state = ReleaseCOMObject(obj)
        return OpaqueCleanable(state, DbgModel.CLEANER.register(owner, state))

    @staticmethod
    def debug_connect(remote_options):
        add_search_paths()
        options = WString(remote_options)
        return wrap_client(DebugClientInternal.try_preferred_interfaces(lambda refiid, ppclient: DbgEngNative.INSTANCE.DebugConnectWide(options, refiid, ppclient)))

    @staticmethod
    def debug_create():
        add_search_paths()
        return wrap_client(DebugClientInternal.try_preferred_interfaces(DbgEngNative.INSTANCE.DebugCreate))

    @staticmethod
    def debug_create_with_options(options):
        add_search_paths()
        dw_opts = DWORD(options)
        return wrap_client(DebugClientInternal.try_preferred_interfaces(lambda refiid, ppclient: DbgEngNative.INSTANCE.DebugCreateEx(refiid, dw_opts, ppclient)))

def add_search_paths():
    # NativeLibrary.addSearchPath("dbghelp.dll", "C:\\Software\\windbg\\amd64")
    # NativeLibrary.addSearchPath("dbgeng.dll", "C:\\Software\\windbg\\amd64")
    # NativeLibrary.addSearchPath("dbgmodel.dll", "C:\\Software\\windbg\\amd64")

DbgModel()
