from abc import ABC, abstractmethod

class ProxyObj(ABC):
    def __init__(self, model: 'ListingModel'):
        self.model = model

    @abstractmethod
    def get_object(self) -> object:
        pass

    def get_listing_layout_model(self) -> 'ListingModel':
        return self.model


class ListingModel:
    # implement this class as needed
    pass
