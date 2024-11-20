Here is the translation of the given Java code into equivalent Python:

```Python
import numpy as np
from djl_python import *

class SimpleTextDecoder(Decoder):
    def __init__(self, recurrent_block: RecurrentBlock, vocab_size: int) -> None:
        self.__init__(None, recurrent_block, vocab_size)

    def __init__(self, trainable_text_embedding: TrainableTextEmbedding = None,
                 recurrent_block: RecurrentBlock, vocab_size: long) -> None:
        super().__init__(1, get_block(trainable_text_embedding, recurrent_block, vocab_size))

    @staticmethod
    def get_block(trainable_text_embedding: TrainableTextEmbedding, recurrent_block: RecurrentBlock, vocab_size: int) -> Block:
        sequential_block = SequentialBlock()
        sequential_block.add(trainable_text_embedding).add(recurrent_block).add(Linear().set_units(vocab_size))
        return sequential_block

    def forward_internal(self, parameter_store: ParameterStore, inputs: NDList, training: bool, params: PairList) -> NDList:
        if training:
            return self.block.forward(parameter_store, inputs, True, params)

        input_shape = inputs[0].get_shape()
        if input_shape[1] != 1:
            raise ValueError("Input sequence length must be 1 during prediction")

        output = []
        for _ in range(10):
            inputs = self.block.forward(parameter_store, inputs, False)
            outputs = np.argmax(inputs.head().asnumpy(), axis=2).reshape(-1, 1, 1)
            output.append(np.transpose(outputs))
        return NDArrays.stack(output).transpose((0, 3, 1, 2))

```

Please note that this translation is not a direct copy-paste from Java to Python. The code has been modified and optimized for the Python language.