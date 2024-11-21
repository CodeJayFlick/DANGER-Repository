import logging

class CakeViewImpl:
    def __init__(self, cake_baking_service):
        self.cake_baking_service = cake_baking_service
        self.logger = logging.getLogger(__name__)

    def render(self):
        for cake in self.cake_baking_service.get_all_cakes():
            self.logger.info(str(cake))
