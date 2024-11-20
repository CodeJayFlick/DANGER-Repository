from abc import ABCMeta, abstractmethod
import xml.etree.ElementTree as ET


class FuncDB(metaclass=ABCMeta):
    @abstractmethod
    def query(self, func) -> list:
        pass

    @abstractmethod
    def restore_xml(self, parser: ET._ElementParser):
        pass

    @abstractmethod
    def save_xml(self, fwrite):
        pass
