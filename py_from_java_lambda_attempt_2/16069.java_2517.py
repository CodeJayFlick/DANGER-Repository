Here is the translation of the given Java code into equivalent Python:

```Python
import tensorflow as tf
from typing import List

class TfOpExecutor:
    def __init__(self, manager: object, eager_session_handle: int, operation: str):
        self.manager = manager
        self.op_handle = None  # type: TFE_Op
        self.closed = False

    def build(self, num_outputs: int) -> List[NDArray]:
        handles = self.build_raw_pointer(num_outputs)
        outputs = [TfNDArray(self.manager, handle) for handle in handles]
        return outputs

    def build_singleton_or_throw(self) -> NDArray:
        handles = self.build_raw_pointer(1)
        try:
            assert len(handles) == 1
        except AssertionError as e:
            for handle in handles:
                tf.free(handle)
            raise e
        return TfNDArray(self.manager, handles[0])

    def build_raw_pointer(self, num_outputs: int) -> List[int]:
        num_return_values = [num_outputs]
        return_values = []
        status = None  # type: TF_Status

        try:
            tf.TFE_Execute(
                self.op_handle,
                return_values,
                num_return_values,
                status
            )
            if not status.ok():
                raise Exception("TFE_Execute failed")
        finally:
            self.close()

    def add_input(self, input_array: NDArray) -> 'TfOpExecutor':
        try:
            tf.TFE_OpAddInput(
                self.op_handle,
                (input_array).get_handle(),
                None  # type: TF_Status
            )
        except Exception as e:
            self.close()
            raise e

    def add_input_list(self, inputs: List[NDArray]) -> 'TfOpExecutor':
        input_handles = [array.get_handle() for array in inputs]
        try:
            tensor_pointers = tf.PointerPointer(input_handles)
            tf.TFE_OpAddInputList(
                self.op_handle,
                tensor_pointers,
                len(inputs),
                None  # type: TF_Status
            )
        except Exception as e:
            self.close()
            raise e

    def set_device(self, device: Device) -> 'TfOpExecutor':
        try:
            if device.get_device_type() == "CPU":
                device_str = "/device:CPU:0"
            elif device.get_device_type() == "GPU":
                device_str = f"/device:GPU:{device.get_device_id()}"
            else:
                raise Exception(f"Unknown device type to TensorFlow Engine: {device}")
            tf.TFE_OpSetDevice(
                self.op_handle,
                device_str,
                None  # type: TF_Status
            )
        except Exception as e:
            self.close()
            raise e

    def add_param(self, name: str, value) -> 'TfOpExecutor':
        if isinstance(value, int):
            tf.TFE_OpSetAttrInt(
                self.op_handle,
                name,
                value
            )
        elif isinstance(value, float):
            tf.TFE_OpSetAttrFloat(
                self.op_handle,
                name,
                value
            )
        elif isinstance(value, bool):
            tf.TFE_OpSetAttrBool(
                self.op_handle,
                name,
                1 if value else 0
            )
        elif isinstance(value, str):
            bytes = value.encode("utf-8")
            tf.TFE_OpSetAttrString(
                self.op_handle,
                name,
                BytePointer(bytes),
                len(bytes)
            )

    def close(self) -> None:
        if not self.closed and self.op_handle is not None:
            try:
                tf.free(self.op_handle)
            except Exception as e:
                pass
            finally:
                self.closed = True

class TfNDArray:
    def __init__(self, manager: object, handle):
        self.manager = manager
        self.handle = handle

    @property
    def get_handle(self) -> int:
        return self.handle

class Device:
    def __init__(self, device_type: str, device_id: int):
        self.device_type = device_type
        self.device_id = device_id

    @property
    def get_device_type(self) -> str:
        return self.device_type

    @property
    def get_device_id(self) -> int:
        return self.device_id

class BytePointer:
    def __init__(self, bytes: bytearray):
        self.bytes = bytes

    @property
    def with_deallocator(self) -> 'BytePointer':
        return self  # This is a workaround for the lack of deallocator in Python.
```

Please note that this translation assumes you have already installed TensorFlow and its dependencies.