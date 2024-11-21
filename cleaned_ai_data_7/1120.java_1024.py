import ctypes

class IDataModelScriptDebugStack:
    IID_IDATA_MODEL_SCRIPT_DEBUG_STACK = "051364DD-E449-443e-9762-FE578F4A5473"

    VTIndices = {
        'GET_FRAME_COUNT': 0,
        'GET_STACK_FRAME': 1,
    }

    def get_frame_count(self):
        raise NotImplementedError

    def get_stack_frame(self, frame_number: int) -> ctypes.POINTER:
        raise NotImplementedError
