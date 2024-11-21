from abc import ABC, abstractmethod


class IPageReader(ABC):
    @abstractmethod
    def get_all_satisfied_page_data(self) -> dict:
        pass

    @abstractmethod
    def get_statistics(self) -> dict:
        pass

    @abstractmethod
    def set_filter(self, filter: object) -> None:
        pass

    @property
    @abstractmethod
    def is_modified(self) -> bool:
        pass


class BatchData(dict):
    pass


class Statistics(dict):
    pass


class Filter(object):
    pass
