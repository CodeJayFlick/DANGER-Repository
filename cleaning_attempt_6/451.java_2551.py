from weakref import WeakValueDictionary as WeakValueHashMap
import immutable

class DebugClass:
    UNINITIALIZED = 0
    KERNEL = 1
    USER_WINDOWS = 2
    IMAGE_FILE = 3


def instance_for(client):
    return DbgEngUtil.lazy_weak_cache(CACHE, client)


PREFERRED_CLIENT_IIDS = {
    IDebugClient7.IID_IDebug_Client7: WrapIDebugClient7,
    IDebugClient6.IID_IDebug_Client6: WrapIDebugClient6,
    IDebugClient5.IID_IDebug_Client5: WrapIDebugClient5,
    IDebugClient4.IID_IDebug_Client4: WrapIDebugClient4,
    IDebugClient3.IID_IDebug_Client3: WrapIDebugClient3,
    IDebugClient2.IID_IDebug_Client2: WrapIDebugClient2,
    IDebugClient.IID_IDebug_Client: WrapIDebugClient
}


def try_preferred_interfaces(supplier):
    return DbgEngUtil.try_preferred_interfaces(DebugClientInternal, PREFERRED_CLIENT_IIDS, supplier)


class DebugClientInternal:
    CACHE = WeakValueHashMap()

    def __init__(self):
        pass

    @staticmethod
    def instance_for(client):
        # same as above
        return DbgEngUtil.lazy_weak_cache(CACHE, client)

    @staticmethod
    def try_preferred_interfaces(supplier):
        # same as above
        return DbgEngUtil.try_preferred_interfaces(DebugClientInternal, PREFERRED_CLIENT_IIDS, supplier)


    def get_jna_client(self):
        pass

    def get_control_internal(self):
        pass


    def end_session_reentrant(self):
        self.end_session(DebugEndSessionFlags.DEBUG_END_REENTRANT)
