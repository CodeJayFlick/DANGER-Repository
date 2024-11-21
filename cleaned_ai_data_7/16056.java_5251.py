import tensorflow as tf
from typing import Tuple, List

class JavacppUtils:
    DEVICE_PATTERN = r"device:([A-Z]PU):(\\d+)"
    
    def __init__(self):
        pass
    
    @staticmethod
    def load_saved_model_bundle(export_dir: str, tags: list[str], config: tf.ConfigProto, run_options: tf.RunOptions) -> Tuple[tf.SavedModelBundle]:
        with tf.device('/device:CPU:0'):
            status = tf.Status()
            
            # Allocate parameters for TF_LoadSessionFromSavedModel
            opts = tf.SessionOptions()
            if config is not None:
                config_bytes = bytes(config.SerializeToString())
                tensorflow.TFE_SetConfig(opts, config_bytes, len(config_bytes), status)
                status.throw_exception_if_not_ok()
                
            run_opts = tf.RunOptions().SerializeToString()
            
            # Load the session
            graph_handle = tf.Graph()
            meta_graph_def = tf.MetaGraphDef()
            session_handle = tensorflow.TF_LoadSessionFromSavedModel(
                opts, 
                run_opts, 
                export_dir.encode(), 
                [tag.encode() for tag in tags], 
                len(tags), 
                graph_handle, 
                meta_graph_def, 
                status
            )
            status.throw_exception_if_not_ok()
            
            # Handle the result
            try:
                return tf.SavedModelBundle(
                    session_handle,
                    graph_handle,
                    meta_graph_def.ParseFromString(session_handle.SerializeToString())
                )
            except InvalidProtocolBufferException as e:
                raise TensorFlowException("Cannot parse MetaGraphDef protocol buffer", e)
    
    @staticmethod
    def get_graph_op_by_name(graph_handle: tf.Graph, operation: str) -> tf.Operation:
        op_handle = None
        
        with graph_handle.lock():
            op_handle = tensorflow.TF_GraphOperationByName(graph_handle, operation.encode())
        
        if op_handle is None or not op_handle.is_valid():
            raise ValueError(f"No Operation named [{operation}] in the Graph")
        
        return op_handle
    
    @staticmethod
    def get_graph_operation_by_name(graph_handle: tf.Graph, operation: str) -> Tuple[tf.Operation, int]:
        colon = operation.rfind(':')
        if colon == -1 or colon == len(operation) - 1:
            return JavacppUtils.get_graph_op_by_name(graph_handle, operation), 0
        
        try:
            op = operation[:colon]
            index = int(operation[colon + 1:])
            return JavacppUtils.get_graph_op_by_name(graph_handle, op), index
        except ValueError as e:
            return JavacppUtils.get_graph_op_by_name(graph_handle, operation), 0
    
    @staticmethod
    def run_session(session_handle: tf.Session, run_options: tf.RunOptions, input_tensor_handles: List[tf.Tensor], 
                   input_op_handles: list[tf.Operation], input_op_indices: list[int], output_op_handles: list[tf.Operation], 
                   output_op_indices: list[int], target_op_handles: list[tf.Operation]) -> List[tf.Tensor]:
        num_inputs = len(input_tensor_handles)
        num_outputs = len(output_op_handles)
        num_targets = len(target_op_handles)
        
        try:
            # TODO: check with sig-jvm if TF_Output here is freed
            inputs = tf.Output(num_inputs)
            input_values = [input_tensor_handle for input_tensor_handle in input_tensor_handles]
            
            outputs = tf.Output(num_outputs)
            output_values = [tf.Tensor() for _ in range(num_outputs)]
            
            targets = [op_handle for op_handle in target_op_handles]
            
            # Set input
            for i, (tensor, _) in enumerate(zip(input_tensor_handles, input_op_handles)):
                inputs.position(i).oper(op_handles[i]).index(input_op_indices[i])
            
            # Run the session
            status = tf.Status()
            tensorflow.TF_SessionRun(
                session_handle,
                run_options.SerializeToString(),
                inputs,
                input_values,
                num_inputs,
                outputs,
                output_values,
                num_outputs,
                targets,
                num_targets,
                None,  # No target op handle needed for now
                status
            )
            status.throw_exception_if_not_ok()
            
            return [output_value for output_value in output_values]
        except Exception as e:
            raise TensorFlowException("Failed to run the session", e)
    
    @staticmethod
    def create_eager_session(async: bool, device_placement_policy: int, config: tf.ConfigProto) -> tf.TFE_Context:
        try:
            opts = tf.TFE_ContextOptions()
            
            if config is not None:
                config_bytes = bytes(config.SerializeToString())
                tensorflow.TFE_ContextOptionsSetConfig(opts, config_bytes, len(config_bytes), status)
                status.throw_exception_if_not_ok()
            
            tensorflow.TFE_ContextOptionsSetAsync(opts, 1 if async else 0)
            tensorflow.TFE_ContextOptionsSetDevicePlacementPolicy(opts, device_placement_policy)
            
            context = tf.TFE_Context(new_context_options=opts, status=status).retain_reference()
            return context
        except Exception as e:
            raise TensorFlowException("Failed to create the eager session", e)
    
    @staticmethod
    def get_device(handle: tf.TensorHandle) -> Device:
        try:
            device_name = tensorflow.TFE_TensorHandleDeviceName(handle, status=status).decode('utf-8')
            return from_tf_device(device_name)
        except Exception as e:
            raise TensorFlowException("Failed to get the device", e)
    
    @staticmethod
    def create_empty_tftensor(shape: tf.Shape, data_type: tf.DataType) -> tf.Tensor:
        d_type = TfDataType.to_tf(data_type)
        dims = shape.get_shape()
        
        num_bytes = 1 if data_type == tf.string else len(dims) * data_type.num_of_bytes
        
        tensor = tf.Tensor(d_type, dims, num_bytes).retain_reference()
        return tensor
    
    @staticmethod
    def create_empty_tfectensor(shape: tf.Shape, data_type: tf.DataType, context: tf.TFE_Context, device: Device) -> tf.TFE_TensorHandle:
        try:
            tensor = JavacppUtils.create_empty_tftensor(shape, data_type)
            
            if device.is_gpu():
                return to_device(tensor.handle, context, device)
            else:
                return tensor.handle
        except Exception as e:
            raise TensorFlowException("Failed to create the empty TF-E Tensor", e)
    
    @staticmethod
    def resolve_tfetensor(handle: tf.TFE_TensorHandle) -> tf.Tensor:
        try:
            tensor = tensorflow.TFE_TensorHandleResolve(handle, status=status).retain_reference()
            return tensor
        except Exception as e:
            raise TensorFlowException("Failed to resolve the TF-E Tensor", e)
    
    @staticmethod
    def set_byte_buffer(handle: tf.TFE_TensorHandle, data: bytes) -> None:
        try:
            with tensorflow.TF_Session() as session:
                status = tf.Status()
                
                # Convert to TF-Tensor
                tensor = tensorflow.TFE_TensorHandleResolve(handle, status=status).retain_reference()
                
                pointer = tensorflow.TF_TensorData(tensor)
                pointer.as_buffer().put(data)
        except Exception as e:
            raise TensorFlowException("Failed to set the byte buffer", e)
    
    @staticmethod
    def get_byte_buffer(handle: tf.TFE_TensorHandle) -> bytes:
        try:
            with tensorflow.TF_Session() as session:
                status = tf.Status()
                
                # Convert to TF-Tensor
                tensor = tensorflow.TFE_TensorHandleResolve(handle, status=status).retain_reference()
                
                pointer = tensorflow.TF_TensorData(tensor)
                return pointer.as_buffer().get().tobytes()
        except Exception as e:
            raise TensorFlowException("Failed to get the byte buffer", e)

    @staticmethod
    def create_string_tensor(dims: List[int], src: list[bytes]) -> Tuple[tf.Tensor, tf.TFE_TensorHandle]:
        try:
            d_type = TfDataType.to_tf(tf.string)
            
            num_bytes = len(src) + 1
            
            tensor = tf.Tensor(d_type, dims, num_bytes).retain_reference()
            
            pointer = tensorflow.TF_TensorData(tensor)
            data = tf.TString(pointer.capacity(num_bytes))
            
            for i, src in enumerate(src):
                tstring = data.get_pointer(i)
                tensorflow.TTString_Copy(tstring, bytes(src), len(src) + 1)
            
            return tensor, handle
        except Exception as e:
            raise TensorFlowException("Failed to create the string tensor", e)

    @staticmethod
    def get_string(handle: tf.TFE_TensorHandle, count: int, charset: str = 'utf-8') -> List[str]:
        try:
            with tensorflow.TF_Session() as session:
                status = tf.Status()
                
                # Convert to TF-Tensor
                tensor = tensorflow.TFE_TensorHandleResolve(handle, status=status).retain_reference()
                
                pointer = tensorflow.TF_TensorData(tensor)
                data = tf.TString(pointer.capacity(len(src) + 1))
                
                ret = []
                for i in range(count):
                    tstring = data.get_pointer(i)
                    size = len(tstring.data_as_string())
                    byte_ptr = tensorflow.TTString_GetDataPointer(tstring).capacity(size)
                    
                    ret.append(byte_ptr.decode(charset, errors='replace'))
            
            return ret
        except Exception as e:
            raise TensorFlowException("Failed to get the string", e)

    @staticmethod
    def create_tfectensor(handle: tf.TFE_TensorHandle) -> tf.TFE_TensorHandle:
        try:
            with tensorflow.TF_Session() as session:
                status = tf.Status()
                
                # Convert to TF-Tensor
                tensor = tensorflow.TFE_TensorHandleResolve(handle, status=status).retain_reference()
                
                return handle
        except Exception as e:
            raise TensorFlowException("Failed to create the TF-E Tensor", e)

    @staticmethod
    def from_tf_device(device: str) -> Device:
        matcher = re.match(DEVICE_PATTERN, device)
        
        if matcher is not None and "CPU" == matcher.group(1):
            return Device.cpu()
        elif matcher is not None and "GPU" == matcher.group(1):
            return Device.gpu(int(matcher.group(2)))
        else:
            raise EngineException(f"Unknown device type to TensorFlow Engine: {device}")

    @staticmethod
    def to_tf_device(device: str) -> str:
        if device.get_device_type() == Device.Type.CPU:
            return "/device:CPU:0"
        elif device.get_device_type() == Device.Type.GPU:
            return f"/device:GPU:{device.get_device_id()}"
        else:
            raise EngineException(f"Unknown device type to TensorFlow Engine: {device}")
