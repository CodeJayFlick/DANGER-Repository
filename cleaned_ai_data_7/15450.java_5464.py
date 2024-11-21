import os
from ai_djl import Translator, NDList, Batchifier
from ai_djl.translate import TranslatorContext
from ai_djl.modality.cv import ImageFactory

class FileTranslator(Translator):
    def __init__(self, translator: Translator) -> None:
        self.translator = translator

    def process_input(self, ctx: TranslatorContext, input_path: str) -> NDList:
        image = ImageFactory.get_instance().from_file(input_path)
        return self.translator.process_input(ctx, [image])

    def process_output(self, ctx: TranslatorContext, output_list: NDList) -> any:
        return self.translator.process_output(ctx, output_list)

    def get_batchifier(self) -> Batchifier:
        return self.translator.get_batchifier()

    def prepare(self, ctx: TranslatorContext) -> None:
        self.translator.prepare(ctx)
