Here is the translation of the Java code into equivalent Python:

```Python
import paddle
from typing import List

class JniUtils:
    def __init__(self):
        pass

    @staticmethod
    def create_nd_array(manager: 'PaddleManager', data, shape, dtype) -> 'PaddleTensor':
        int_shape = [int(x) for x in shape]
        handle = paddle.create_tensor(data, len(data), tuple(int_shape), dtype)
        return manager.create_internal(data, handle)

    @staticmethod
    def get_dtype_from_nd(array: 'PaddleTensor') -> str:
        type_ = array.get_data_type()
        if type_ == 1:
            return "float32"
        elif type_ == 2:
            return "int64"

    @staticmethod
    def get_buffer_from_nd(array: 'PaddleTensor') -> bytes:
        buffer = paddle.get_tensor_data(array)
        return buffer.tobytes()

    @staticmethod
    def get_shape_from_nd(array: 'PaddleTensor') -> List[int]:
        shape = array.shape()
        return list(shape)

    @staticmethod
    def set_name_nd(array: 'PaddleTensor', name) -> None:
        paddle.set_tensor_name(array, name)

    @staticmethod
    def get_name_from_nd(array: 'PaddleTensor') -> str:
        return paddle.get_tensor_name(array)

    @staticmethod
    def set_lod_nd(array: 'PaddleTensor', lod) -> None:
        paddle.set_tensor_loD(array, lod)

    @staticmethod
    def get_lod_from_nd(array: 'PaddleTensor') -> List[List[int]]:
        lod = array.lod()
        return list(lod)

    @staticmethod
    def delete_nd(handle):
        paddle.delete_tensor(handle)

    @staticmethod
    def create_config(model_dir, param_dir, device) -> int:
        deviceId = device.get_device_id()
        return paddle.create_analysis_config(model_dir, param_dir, deviceId)

    @staticmethod
    def enable_mkldnn(config: int) -> None:
        paddle.analysis_config_enable_mkldnn(config)

    @staticmethod
    def remove_pass(config: int, pass_) -> None:
        paddle.analysis_config_remove_pass(config, pass_)

    @staticmethod
    def disable_glog(config: int) -> None:
        paddle.analysis_config_disable_glog(config)

    @staticmethod
    def cpu_math_library_num_threads(config: int, thread: int) -> None:
        paddle.analysis_config_cml_num_threads(config, thread)

    @staticmethod
    def switch_ir_optim(config: int, condition: bool) -> None:
        paddle.analysis_config_switch_ir_optim(config, condition)

    @staticmethod
    def use_feed_fetch_op(config: int) -> None:
        paddle.use_feed_fetch_op(config)

    @staticmethod
    def delete_config(config: int) -> None:
        paddle.delete_analysis_config(config)

    @staticmethod
    def create_predictor(config: int) -> 'PaddlePredictor':
        return paddle.create_predictor(config)

    @staticmethod
    def clone_predictor(predictor: 'PaddlePredictor') -> 'PaddlePredictor':
        return paddle.clone_predictor(predictor.get_handle())

    @staticmethod
    def delete_predictor(predictor: 'PaddlePredictor') -> None:
        paddle.delete_predictor(predictor.get_handle())

    @staticmethod
    def predictor_forward(
            predictor: 'PaddlePredictor', inputs, input_names) -> List['PaddleTensor']:
        output_handles = []
        for i in range(len(inputs)):
            outputs.append(paddle.run_inference(predictor.get_handle(), [inputs[i].get_handle()]))
        return [manager.create_internal(None, handle) for handle in output_handles]

    @staticmethod
    def get_input_names(predictor: 'PaddlePredictor') -> List[str]:
        return paddle.get_input_names(predictor.get_handle())

    @staticmethod
    def get_version():
        return "2.0.2"
```

Please note that this translation is not a direct conversion from Java to Python, but rather an equivalent implementation in Python using the Paddle library.