class WrapIDebugHostMemory1:
    def __init__(self):
        pass

    def read_bytes(self, context, location, buffer, bufferSize, bytesRead):
        # Assuming _invokeHR and VTIndices1 are defined elsewhere in your program
        return self._invoke_hr(VTIndices1.READ_BYTES, context, location, buffer, bufferSize, bytesRead)

    def write_bytes(self, context, location, buffer, bufferSize, bytesWritten):
        return self._invoke_hr(VTIndices1.WRITE_BYTES, context, location, buffer, bufferSize, bytesWritten)

    def read_pointers(self, context, location, count, pointers):
        return self._invoke_hr(VTIndices1.READ_POINTERS, context, location, count, pointers)

    def write_pointers(self, context, location, count, pointers):
        return self._invoke_hr(VTIndices1.WRITE_POINTERS, context, location, count, pointers)

    def get_display_string_for_location(self, context, location, verbose, locationName):
        return self._invoke_hr(VTIndices1.GET_DISPLAY_STRING_FOR_LOCATION, context, location, verbose, locationName)


class ByReference(WrapIDebugHostMemory1):
    pass
