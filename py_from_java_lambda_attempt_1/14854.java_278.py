Here is the translation of the given Java code into Python:

```Python
class Service:
    def __init__(self):
        self.sd = None  # Assuming this will be set later

    @staticmethod
    def get_logger():
        import logging
        logger = logging.getLogger(__name__)
        return logger

    def execute(self, saga: 'Saga') -> 'Saga':
        next_saga = saga
        chapter_name = saga.current.name
        if chapter_name == self.__class__.__name__:
            if saga.is_forward:
                next_saga = self.process(saga)
                next_value = next_saga.current.value
                if next_saga.is_current_success:
                    next_saga.forward()
                else:
                    next_saga.back()
            else:
                next_saga = self.rollback(saga)
                next_value = next_saga.current.value
                next_saga.back()

        if self.is_saga_finished(next_saga):
            return next_saga

        next_saga.set_current_value(next_value)

    def process(self, saga: 'Saga') -> 'Saga':
        in_value = saga.current.value
        logger = Service.get_logger()
        logger.info(f"The chapter '{self.__class__.__name__}' has been started. The data {in_value} has been stored or calculated successfully")
        saga.set_current_status(Saga.ChapterResult.SUCCESS)
        saga.set_current_value(in_value)
        return saga

    def rollback(self, saga: 'Saga') -> 'Saga':
        in_value = saga.current.value
        logger = Service.get_logger()
        logger.info(f"The Rollback for a chapter '{self.__class__.__name__}' has been started. The data {in_value} has been rolled back successfully")
        saga.set_current_status(Saga.ChapterResult.ROLLBACK)
        saga.set_current_value(in_value)
        return saga

    def is_saga_finished(self, saga: 'Saga') -> bool:
        if not saga.is_present():
            saga.set_finished(True)
            logger = Service.get_logger()
            logger.info(f" the saga has been finished with {saga.result} status")
            return True
        return False


class Saga:
    def __init__(self):
        self.current = None  # Assuming this will be set later

    @property
    def current(self) -> 'SagaChapter':
        return self._current

    @current.setter
    def current(self, value: 'SagaChapter'):
        self._current = value


class SagaChapter:
    def __init__(self):
        pass

    @property
    def name(self) -> str:
        pass  # Assuming this will be set later

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def is_forward(self) -> bool:
        return False  # Assuming this will be set later

    @is_forward.setter
    def is_forward(self, value: bool):
        self._is_forward = value

    @property
    def current_value(self) -> str:
        pass  # Assuming this will be set later

    @current_value.setter
    def current_value(self, value: str):
        self._current_value = value

    @property
    def is_current_success(self) -> bool:
        return False  # Assuming this will be set later

    @is_current_success.setter
    def is_current_success(self, value: bool):
        self._is_current_success = value


class ServiceDiscoveryService:
    pass  # This class needs to be implemented in Python as well
```

Note that the `Saga`, `SagaChapter` and `ServiceDiscoveryService` classes are not fully implemented here. You would need to implement these based on your specific requirements.