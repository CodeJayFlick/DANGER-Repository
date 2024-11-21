import uuid
from ai_djl_ndarray import NDArrayAdapter, BaseNDManager, NDManager, Shape, DataType


class TrtNDArray(NDArrayAdapter):
    def __init__(self,
                 manager: 'TrtNDManager',
                 alternative_manager: 'BaseNDManager',
                 data: bytes,
                 shape: tuple,
                 data_type: str) -> None:
        super().__init__(manager=manager, 
                         alternative_manager=alternative_manager, 
                         shape=shape, 
                         data_type=data_type, 
                         uid=str(uuid.uuid4()))
        self.data = data

    def intern(self, replaced: 'TrtNDArray') -> None:
        if isinstance(replaced, TrtNDArray):
            self.data = replaced.data
        else:
            raise TypeError("Only a TrtNDArray can be internd")

    def detach(self) -> None:
        # equivalent to manager.detachInternal(getUid())
        pass

    def to_byte_buffer(self) -> bytes:
        return self.data

    def set_data(self, data: memoryview) -> None:
        size = len(self.shape)
        BaseNDManager.validate_buffer_size(data, self.data_type, size)
        BaseNDManager.copy_buffer(data, self.data)

class TrtNDManager(BaseNDManager):
    @staticmethod
    def get_system_manager() -> 'BaseNDManager':
        # equivalent to manager.getSystemManager()
        pass

# usage example:
manager = TrtNDManager()
alternative_manager = BaseNDManager()
data = b'your_data_here'
shape = (1, 2)  # or any other shape
data_type = "float32"
nd_array = TrtNDArray(manager=manager,
                       alternative_manager=alternative_manager,
                       data=data,
                       shape=shape,
                       data_type=data_type)
