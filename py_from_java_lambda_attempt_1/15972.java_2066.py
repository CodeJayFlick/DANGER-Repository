Here's a translation of your Java code into equivalent Python:

```Python
class OrtUtils:
    def __init__(self):
        pass

    @staticmethod
    def to_tensor(env, data, shape, data_type):
        if len(shape) == 0:
            raise ValueError("OnnxRuntime doesn't support 0 length tensor.")
        
        if isinstance(data, bytes):
            data = data_type.from_numpy_array(np.array(data))
        
        try:
            return OnnxTensor.create_tensor(env, data, tuple(shape))
        except OrtException as e:
            raise EngineException(e)

    @staticmethod
    def to_tensor(env, inputs, shape):
        return OnnxTensor.create_tensor(env, inputs, tuple(shape))

    @staticmethod
    def to_data_type(java_type):
        if java_type == 'FLOAT':
            return DataType.FLOAT32
        elif java_type == 'DOUBLE':
            return DataType.FLOAT64
        elif java_type == 'INT8':
            return DataType.INT8
        elif java_type == 'UINT8':
            return DataType.UINT8
        elif java_type == 'INT32':
            return DataType.INT32
        elif java_type == 'INT64':
            return DataType.INT64
        elif java_type == 'BOOL':
            return DataType.BOOLEAN
        elif java_type == 'STRING':
            return DataType.STRING
        else:
            raise ValueError(f"type is not supported: {java_type}")
```

Please note that this translation assumes you have the following Python libraries installed:

- numpy (for handling arrays)
- onnxruntime (for creating OnnxTensors)

Also, please replace `OnnxTensor`, `OrtEnvironment`, and `EngineException` with your actual imports.