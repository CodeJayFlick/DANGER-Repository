import logging
from typing import Any, Dict, List, Tuple
from pathlib import Path
import os
import subprocess
import requests
import json
import numpy as np  # noqa: F401

class ServingTranslatorFactory:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_supported_types(self) -> set[Tuple[type, type]]:
        return {tuple([Input, Output])}

    def new_instance(
            self,
            input_type: Any,
            output_type: Any,
            model: Any,
            arguments: Dict[str, Any]
    ) -> Tuple[Any, ...]:
        if not is_supported(input_type, output_type):
            raise ValueError("Unsupported input/output types.")

        model_dir = Path(model.get_model_path())
        factory_class = arguments.get('translator_factory')
        if factory_class and factory_class:
            translator_factory = self.load_translator_factory(factory_class)
            if translator_factory and isinstance(translator_factory, ServingTranslatorFactory) \
                    and translator_factory.is_supported(input_type, output_type):
                return translator_factory.new_instance(input_type, output_type, model, arguments)

        class_name = arguments.get('translator')
        lib_path = Path(model_dir / 'libs' or model_dir / 'lib')

        if not os.path.exists(lib_path):
            return self.load_default_translator(arguments)

        serving_translator = self.find_translator(lib_path, class_name)
        if serving_translator:
            serving_translator.set_arguments(arguments)
            return serving_translator

        return self.load_default_translator(arguments)

    def load_translator_factory(self, factory_class: str) -> Any:
        try:
            clazz = type('TranslatorFactory', (), {'__module__': 'ai.djl.translate'})
            subclass = type('Subclass', (clazz,), {'__module__': 'ai.djl.translate'})
            constructor = subclass.__init__
            return constructor()
        except Exception as e:
            self.logger.debug(f"Not able to load TranslatorFactory: {factory_class}", e)
        return None

    def find_translator(self, lib_path: Path, class_name: str) -> Any:
        try:
            for file in os.listdir(lib_path):
                if file.endswith('.class'):
                    serving_translator = self.init_translator(class_name)
                    if serving_translator:
                        return serving_translator
        except Exception as e:
            self.logger.debug(f"Failed to find Translator", e)

    def init_translator(self, class_name: str) -> Any:
        try:
            clazz = type('Translator', (), {'__module__': 'ai.djl.translate'})
            subclass = type('Subclass', (clazz,), {'__module__': 'ai.djl.translate'})
            constructor = subclass.__init__
            return constructor()
        except Exception as e:
            self.logger.debug(f"Not able to load Translator: {class_name}", e)
        return None

    def compile_java_class(self, dir_path: Path) -> Any:
        try:
            if not os.path.exists(dir_path):
                logging.info("Directory does not exist", dir_path)
                return
            files = [file for file in os.listdir(dir_path) if file.endswith('.java')]
            subprocess.run(['javac', *files])
        except Exception as e:
            self.logger.warning(f"Failed to compile bundled java file", e)

    def load_default_translator(self, arguments: Dict[str, Any]) -> Tuple[Any, ...]:
        app_name = arguments.get('application')
        if app_name and app_name:
            application = Application.of(app_name)
            if application == Application.CV.IMAGE_CLASSIFICATION:
                return self.image_classification_translator(arguments)

    def image_classification_translator(self, arguments: Dict[str, Any]) -> Tuple[Any, ...]:
        batchifier = Batchifier.from_string(arguments.get('batchifier', 'none'))
        return RawTranslator(batchifier)


class TranslatorFactory:
    pass


class ServingTranslator(Translator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def set_arguments(self, arguments: Dict[str, Any]) -> None:
        # TODO
        pass

    def process_input(self, ctx: TranslatorContext, input: Input) -> NDList:
        manager = ctx.get_nd_manager()
        try:
            return input.data_as_nd_list(manager)
        except Exception as e:
            raise TranslateException("Input is not a NDList data type", e)

    def process_output(self, ctx: TranslatorContext, list: NDList) -> Output:
        output = Output()
        # TODO
        pass


class RawTranslator(ServingTranslator):
    def __init__(self, batchifier: Batchifier):
        self.batchifier = batchifier

    @property
    def batchifier(self) -> Batchifier:
        return self._batchifier

    @batchifier.setter
    def batchifier(self, value: Batchifier):
        self._batchifier = value


class Application:
    CV = 'cv'


class Input:
    pass


class Output:
    pass


class NDList(np.ndarray):
    pass


class TranslatorContext:
    def get_nd_manager(self) -> Any:
        # TODO
        pass

# Usage example:

factory = ServingTranslatorFactory()
translator = factory.new_instance(Input, Output, model, arguments)
