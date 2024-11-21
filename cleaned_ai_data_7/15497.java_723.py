import torch
from transformers import EncoderDecoderModel, DecoderOnlyBlockEmbeddings, TrainableTextEmbedding
from typing import List

class SimpleText2TextTranslator:
    def __init__(self):
        self.tokenizer = None  # Initialize tokenizer later
        self.source_embedding = None
        self.target_embedding = None
        self.text_processors: List[object] = []

    def process_output(self, ctx, list) -> str:
        if len(list.shape) > 2:
            raise ValueError("Input must correspond to one sentence. Shape must be of 2 or less dimensions")

        if not self.target_embedding:
            model = ctx.model
            encoder_decoder = EncoderDecoderModel(model)
            decoder = encoder_decoder.decoder
            sequential_block = decoder.children[0].children[0]
            self.target_embedding = TrainableTextEmbedding(sequential_block)

        output = []
        for token in self.target_embedding.unembed_text(list.to(torch.int32, False).flatten()):
            if token == "<eos>":
                break
            output.append(token)
        return self.tokenizer.build_sentence(output)

    def process_input(self, ctx, input: str) -> torch.Tensor:
        model = ctx.model
        if not self.source_embedding:
            encoder_decoder = EncoderDecoderModel(model)
            encoder = encoder_decoder.encoder
            sequential_block = encoder.children[0].children[0]
            self.source_embedding = TrainableTextEmbedding(sequential_block)

        tokens = [input]
        for text_processor in self.text_processors:
            tokens = text_processor.preprocess(tokens)

        return torch.tensor(self.source_embedding.preprocess_text_to_embed(tokens), dtype=torch.float32)
