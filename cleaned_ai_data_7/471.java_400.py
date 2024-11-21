import ctypes

class WrapCallbackIDebugOutputCallbacksWide:
    def __init__(self, cb):
        self.cb = cb
        self.listener = None

    def set_listener(self, listener):
        self.listener = listener

    def get_pointer(self):
        return self.listener.get_pointer() if self.listener else None

    def query_interface(self, refid, ppv_object):
        if not ppv_object:
            raise ctypes.WinError(ctypes.error.E_POINTER)
        elif refid.value == IDebugOutputCallbacksWide.IID_IDEBUG_OUTPUT_CALLBACKS_WIDE:
            ppv_object.value = self.get_pointer()
            return 0
        elif refid.value == IUnknown.IID_IUNKNOWN:
            ppv_object.value = self.get_pointer()
            return 0
        raise ctypes.WinError(ctypes.error.E_NOINTERFACE)

    def add_ref(self):
        return 0

    def release(self):
        return 0

    def output(self, mask, text):
        try:
            self.cb.output(mask, str(text))
            return 0
        except Exception as e:
            raise ctypes.WinError(ctypes.error.E_UNEXPECTED)
