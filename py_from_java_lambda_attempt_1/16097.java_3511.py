Here is a translation of the Java code into equivalent Python code:

```Python
import ctypes

class TrtLibrary:
    _LIB = None

    def __init__(self):
        pass

    @staticmethod
    def init_plugins(namespace: str, log_level: int) -> None:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to initialize plugins
        ctypes.pythonapi.init_plugins(namespace.encode('utf-8'), log_level)

    @staticmethod
    def load_trt_model(model_type: int, model_path: str, device_id: int, option_keys: list[str], option_values: list[str]) -> long:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to load a TensorRT model
        return ctypes.c_long(long(TrtLibrary._LIB.load_trt_model(model_type, model_path.encode('utf-8'), device_id, [key.encode('utf-8') for key in option_keys], [value.encode('utf-8') for value in option_values])))

    @staticmethod
    def delete_trt_model(model_handle: long) -> None:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to delete a TensorRT model
        ctypes.pythonapi.delete_trt_model(model_handle)

    @staticmethod
    def get_input_names(model_handle: long) -> list[str]:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to get input names of a TensorRT model
        return [name.decode('utf-8') for name in ctypes.pythonapi.get_input_names(model_handle)]

    @staticmethod
    def get_input_data_types(model_handle: long) -> list[int]:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to get input data types of a TensorRT model
        return [int(type) for type in ctypes.pythonapi.get_input_data_types(model_handle)]

    @staticmethod
    def get_output_names(model_handle: long) -> list[str]:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to get output names of a TensorRT model
        return [name.decode('utf-8') for name in ctypes.pythonapi.get_output_names(model_handle)]

    @staticmethod
    def get_output_data_types(model_handle: long) -> list[int]:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to get output data types of a TensorRT model
        return [int(type) for type in ctypes.pythonapi.get_output_data_types(model_handle)]

    @staticmethod
    def create_session(model_handle: long) -> long:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to create a TensorRT session
        return ctypes.c_long(long(TrtLibrary._LIB.create_session(model_handle)))

    @staticmethod
    def delete_session(session_handle: long) -> None:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to delete a TensorRT session
        ctypes.pythonapi.delete_session(session_handle)

    @staticmethod
    def get_shape(session_handle: long, name: str) -> list[int]:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to get shape of a TensorRT session
        return [int(dim) for dim in ctypes.pythonapi.get_shape(session_handle.encode('utf-8'), name.encode('utf-8'))]

    @staticmethod
    def bind(session_handle: long, name: str, buffer: bytes) -> None:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to bind a TensorRT session
        ctypes.pythonapi.bind(session_handle.encode('utf-8'), name.encode('utf-8'), buffer)

    @staticmethod
    def run_trt_model(session_handle: long) -> None:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to run a TensorRT model
        ctypes.pythonapi.run_trt_model(session_handle.encode('utf-8'))

    @staticmethod
    def get_trt_version() -> int:
        if not TrtLibrary._LIB:
            raise Exception("TensorRT Engine is not initialized")
        # Call the native method to get the version of TensorRT engine
        return ctypes.pythonapi.get_trt_version()
```

Note that this code does not include any actual native methods. The `native` keyword in Java indicates a call to a native library, which would typically be implemented using JNI (Java Native Interface) or another mechanism for calling C/C++ functions from Java.

In Python, you can use the `ctypes` module to load and call external libraries. However, this code does not include any actual calls to an external library; it simply provides a translation of the original Java code into equivalent Python syntax.