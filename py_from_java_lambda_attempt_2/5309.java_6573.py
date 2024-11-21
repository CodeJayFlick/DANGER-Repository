Here is the translation of the given Java code into equivalent Python:

```Python
from abc import ABCMeta, abstractmethod
import logging


class Exporter(metaclass=ABCMeta):
    def __init__(self, name: str, extension: str, help_location: 'HelpLocation') -> None:
        self._name = Validate.not_none(name)
        self._extension = Validate.not_none(extension)
        self._help_location = help_location
        self._log = logging.getLogger(__name__)
        self._provider = None

    @property
    def name(self) -> str:
        return self._name

    @property
    def default_file_extension(self) -> str:
        return self._extension

    @property
    def help_location(self) -> 'HelpLocation':
        return self._help_location

    @property
    def message_log(self) -> logging.Logger:
        return self._log

    @message_log.setter
    def set_message_log(self, log: logging.Logger):
        self._log = log

    @property
    def provider(self) -> 'ServiceProvider':
        return self._provider

    @provider.setter
    def set_provider(self, provider: 'ServiceProvider'):
        self._provider = provider

    def can_export_domain_object(self, domain_object_class: type) -> bool:
        from ghidra.program.model.address import AddressSetView
        if issubclass(domain_object_class, DomainObject):
            return True
        elif Program in [cls for cls in domain_object_class.__mro__]:
            return True
        else:
            return False

    def supports_partial_export(self) -> bool:
        return True


class Option(metaclass=ABCMeta):
    @abstractmethod
    pass


class DomainObjectService(metaclass=ABCMeta):
    @abstractmethod
    pass


class ServiceProvider(metaclass=ABCMeta):
    @abstractmethod
    pass


class HelpLocation(metaclass=ABCMeta):
    @abstractmethod
    pass


class ExporterException(Exception):
    pass


class OptionException(Exception):
    pass

```

Note: This is a direct translation of the given Java code into equivalent Python. The original code was written in Java, and it seems that some classes (like `DomainObject`, `Program`, etc.) are not defined here.