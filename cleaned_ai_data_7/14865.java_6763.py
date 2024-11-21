import logging

class Service:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def get_name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def process(self, value: object) -> dict:
        self.logger.info(f"The chapter '{self.get_name()}' has been started. The data {value} has been stored or calculated successfully")
        return {"status": "success", "data": value}

    def rollback(self, value: object) -> dict:
        self.logger.info(f"Rollback for a chapter '{self.get_name()}' has been started. The data {value} has been rolled back successfully")
        return {"status": "success", "data": value}
