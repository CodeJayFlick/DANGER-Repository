from abc import ABC, abstractmethod
import io
from typing import Collection, List, Any

class Loader(ABC):
    COMMAND_LINE_ARG_PREFIX = "-loader"

    def find_supported_load_specs(self, provider: 'ByteProvider') -> Collection['LoadSpec']:
        pass  # implement this method in your subclass

    @abstractmethod
    def load(self, provider: 'ByteProvider', name: str, folder: 'DomainFolder', 
             load_spec: 'LoadSpec', options: List[Any], message_log: Any, consumer: Any, monitor: Any) -> List['DomainObject']:
        pass  # implement this method in your subclass

    @abstractmethod
    def load_into(self, provider: 'ByteProvider', load_spec: 'LoadSpec', options: List[Any], 
                  message_log: Any, program: 'Program', monitor: Any) -> bool:
        pass  # implement this method in your subclass

    def get_default_options(self, provider: 'ByteProvider', load_spec: 'LoadSpec', domain_object: 'DomainObject', 
                             load_into_program: bool) -> List[Any]:
        return []  # implement this method in your subclass

    @abstractmethod
    def validate_options(self, provider: 'ByteProvider', load_spec: 'LoadSpec', options: List[Any], program: Any) -> str:
        pass  # implement this method in your subclass

    def get_name(self) -> str:
        return ""  # implement this method in your subclass

    @abstractmethod
    def get_tier(self) -> 'LoaderTier':
        pass  # implement this method in your subclass

    @abstractmethod
    def get_tier_priority(self) -> int:
        pass  # implement this method in your subclass

    def get_preferred_file_name(self, provider: 'ByteProvider') -> str:
        fsrl = provider.get_fsrl()
        name = (fsrl is not None) and fsrl.name or provider.name
        return name.replace("[\\\\:|]+", "/")

    @abstractmethod
    def supports_load_into_program(self) -> bool:
        pass  # implement this method in your subclass

    def __lt__(self, other: 'Loader') -> bool:
        compare_tiers = self.get_tier() < other.get_tier()
        if not compare_tiers:
            return self.get_tier_priority() - other.get_tier_priority() < 0
        else:
            return True

class LoaderTier(ABC):
    @abstractmethod
    def __lt__(self, other: 'LoaderTier') -> bool:
        pass  # implement this method in your subclass
