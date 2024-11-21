class X_IDebugHostBaseClass:
    IID_IDEBUG_HOST_BASE_CLASS = "B94D57D2-390B-40f7-B5B4-B6DB897D974B"

    class VTIndicesX:
        start = 0

        def __init__(self):
            pass

        def get_index(self):
            return self.start + self.ordinal()

    def GetOffset(self, offset: int) -> None:
        # This method is equivalent to the Java HRESULT GetOffset(ULONGLONGByReference offset);
        pass
