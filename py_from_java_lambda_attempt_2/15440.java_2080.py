Here is a translation of the provided Java code into equivalent Python:

```Python
import abc
from typing import Any, Dict, Type

class TranslatorFactory:
    def __init__(self):
        pass

    @abc.abstractmethod
    def new_instance(self) -> 'Translator':
        raise NotImplementedError


class InstanceSegmentationTranslatorFactory(TranslatorFactory):

    def new_instance(self,
                     input: type,
                     output: type,
                     model: Any,
                     arguments: Dict[str, Any]) -> Translator:
        if (input == Image and isinstance(output, DetectedObjects)):
            return InstanceSegmentationTranslator(arguments).build()
        elif (isinstance(input, Path) and isinstance(output, DetectedObjects)):
            return FileTranslator(InstanceSegmentationTranslator(arguments).build())
        elif (isinstance(input, URL) and isinstance(output, DetectedObjects)):
            return UrlTranslator(InstanceSegmentationTranslator(arguments).build())
        elif (isinstance(input, InputStream) and isinstance(output, DetectedObjects)):
            return InputStreamTranslator(
                InstanceSegmentationTranslator(arguments).build())
        elif (input == Input and output == Output):
            # This part is not present in the original Java code
            pass  # Add your logic here
        else:
            raise ValueError("Unsupported input/output types.")


class Translator(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def build(self) -> Any:
        raise NotImplementedError


class InstanceSegmentationTranslator(Translator):
    def __init__(self, arguments: Dict[str, Any]):
        self.arguments = arguments

    def build(self) -> Any:
        # Add your logic here to create the translator instance
        pass  # Replace this with actual implementation


# Example usage:

factory = InstanceSegmentationTranslatorFactory()
translator = factory.new_instance(Image, DetectedObjects, None, {})
```

Please note that Python does not have direct equivalent of Java's `Class` type. In the above code, I used `type` for representing classes and `isinstance()` function to check if an object is instance of a class.

Also, in the original Java code there was no implementation provided for `ImageServingTranslator`. So, it has been left as comment in Python translation.