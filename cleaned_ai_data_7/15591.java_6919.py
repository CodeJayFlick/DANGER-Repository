import numpy as np
from djl.basic import NDArray, Function
from djl.nn import AbstractBlock, Linear, BatchNorm
from djl.training import ParameterStore
from typing import List

class BertMaskedLanguageModelBlock(AbstractBlock):
    def __init__(self, bert_block: 'BertBlock', hidden_activation: Function) -> None:
        super().__init__()
        self.sequence_projection = Linear(1, units=bert_block.embedding_size)
        self.sequence_norm = BatchNorm(axis=1)
        self.dictionary_bias = Parameter(name='dictionaryBias', shape=(bert_block.token_dictionary_size,))
        self.hidden_activation = hidden_activation

    @staticmethod
    def gather_from_indices(sequences: NDArray, indices: NDArray) -> NDArray:
        batch_size = sequences.shape[0]
        sequence_length = sequences.shape[1]
        width = sequences.shape[2]
        indices_per_sequence = indices.shape[1]

        # create a list of offsets for each sequence
        sequence_offsets = np.arange(batch_size).reshape(-1, 1) * sequence_length

        absolute_indices = indices + sequence_offsets.reshape(1, -1)
        flattened_sequences = sequences.reshape((batch_size*sequence_length), width)

        return MissingOps.gather_nd(flattened_sequences, absolute_indices)

    def initialize_child_blocks(self, manager: 'NDManager', data_type: str, input_shapes: List[Shape]) -> None:
        self.input_names = ['sequence', 'maskedIndices', 'embeddingTable']
        width = input_shapes[0].shape[2]
        self.sequence_projection.initialize(manager, data_type, Shape(-1, width))
        self.sequence_norm.initialize(manager, data_type, Shape(-1, width))

    def forward_internal(self, ps: ParameterStore, inputs: List[NDArray], training: bool) -> NDList:
        sequence_output = inputs[0]
        masked_indices = inputs[1]
        embedding_table = inputs[2]

        try:
            scope = NDManager.sub_manager_of(sequence_output)
            scope.temp_attach_all(*inputs)

            gathered_tokens = self.gather_from_indices(sequence_output, masked_indices)  # (B * I, E)
            projected_tokens = self.hidden_activation(self.sequence_projection.forward(ps, [gathered_tokens], training)[0])  # (B * I, E)
            normalized_tokens = self.sequence_norm.forward(ps, [projected_tokens], training)[0]  # (B * I, E)

            embedding_transposed = embedding_table.transpose()
            logits_with_bias = (normalized_tokens.dot(embedding_transposed) + ps.get_value(self.dictionary_bias)).log_softmax(1)  # (B * I, D)
        finally:
            scope.ret([logits_with_bias])

    def get_output_shapes(self, input_shapes: List[Shape]) -> List[Shape]:
        batch_size = input_shapes[0].shape[0]
        index_count = input_shapes[1].shape[1]
        dictionary_size = input_shapes[2].shape[0]

        return [Shape((batch_size*index_count), dictionary_size)]
