import ctypes.util.find_library
from dlrengine import DLRManager

class DlrSymbolBlock:
    def __init__(self, manager: DLRManager, handle):
        self.handle = handle
        self.manager = manager

    def forward(self, parameter_store, inputs, training=False, params=None):
        model_handle = int(self.handle)
        
        # TODO maybe verify the number of inputs
        for i in range(len(inputs)):
            array = self.manager.from_ndarray(inputs[i])
            JniUtils.set_dlr_input(model_handle, array, i)

        JniUtils.run_dlr_model(model_handle)
        return [self.manager.to_ndarray(JniUtils.get_dlr_output(model_handle))]

    def close(self):
        handle = int(self.handle)
        if handle is not None:
            JniUtils.delete_dlr_model(handle)
