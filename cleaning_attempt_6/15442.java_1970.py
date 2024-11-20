from abc import ABC, abstractmethod
import typing as t

class ObjectDetectionTranslatorFactory(ABC):
    SUPPORTED_TYPES: set[t.Tuple[type, type]] = {
        (Image, DetectedObjects),
        (Path, DetectedObjects),
        (URL, DetectedObjects),
        (InputStream, DetectedObjects),
        (Input, Output)
    }

    @abstractmethod
    def get_supported_types(self) -> t.Set[t.Tuple[type, type]]:
        pass

class Image(t.Generic):
    pass

class DetectedObjects:
    pass

class Input:
    pass

class Output:
    pass

class URL:
    pass

class InputStream:
    pass

class Path:
    pass
