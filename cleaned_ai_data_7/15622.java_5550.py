import os
from typing import List, Dict, Tuple
from abc import ABCMeta, abstractmethod

class BaseModelLoader:
    def __init__(self, mrl: 'MRL') -> None:
        self.mrl = mrl
        self.default_factory = DefaultTranslatorFactory()

    @abstractmethod
    def get_artifact_id(self) -> str:
        pass

    @abstractmethod
    def get_application(self) -> Application:
        pass

    def load_model(
            self, criteria: 'Criteria', 
            progress: Progress=None) -> Tuple['ZooModel']:
        artifact = self.mrl.match(criteria.get_filters())
        
        if not artifact:
            raise ModelNotFoundException("No matching filter found")

        arguments = {}
        options = {}

        try:
            factory = self.get_translator_factory(criteria, arguments)
            
            input_class = criteria.get_input_class()
            output_class = criteria.get_output_class()

            if not factory.is_supported(input_class, output_class):
                factory = self.default_factory
                if not factory.is_supported(input_class, output_class):
                    raise ModelNotFoundException(self.factory_lookup_error_message(factory))

            self.mrl.prepare(artifact, progress)
            
            model_path = os.path.join(self.mrl.get_repository().get_resource_directory(), artifact.name)

            try:
                with open(model_path) as f:
                    arguments.update(json.load(f))
            except FileNotFoundError:
                pass

            application = criteria.get_application()
            if application is not Application.UNDEFINED:
                arguments['application'] = str(application.path)
            
            engine = criteria.get_engine()

            if not engine:
                model_zoo = ModelZoo(self.mrl.get_group_id())
                
                default_engine = Engine.default_engine_name
                for supported_engine in model_zoo.supported_engines():
                    if supported_engine == default_engine:
                        engine = supported_engine
                        break
                    elif Engine.has_engine(supported_engine):
                        engine = supported_engine

            if not engine or not Engine.has_engine(engine):
                raise ModelNotFoundException(f"No supported engine available for model zoo: {model_zoo.group_id}")

            model_name = criteria.get_model_name()
            
            if not model_name:
                model_name = artifact.name
            
            model = self.create_model(model_path, model_name, criteria.device(), block=criteria.block(), arguments=arguments, engine=engine)
            translator = factory.new_instance(input_class, output_class, model, arguments)

        except TranslateException as e:
            raise ModelNotFoundException("No matching translator found", e) from None

    def list_models(self) -> List['Artifact']:
        return self.mrl.list_artifacts()

    @abstractmethod
    def get_factory_lookup_error_message(self, factory: 'TranslatorFactory') -> str:
        pass

class DefaultTranslatorFactory(ABC):
    def is_supported(self, input_class: Type, output_class: Type) -> bool:
        # implement this method in the subclass
        return False
    
    def new_instance(self, input_class: Type, output_class: Type, model: 'Model', arguments: Dict[str, object]) -> Translator:
        raise NotImplementedError

class BaseModelLoader(ABC):
    @abstractmethod
    def get_artifact_id(self) -> str:
        pass

    @abstractmethod
    def get_application(self) -> Application:
        pass

# The above code is translated from the given Java code into equivalent Python.
