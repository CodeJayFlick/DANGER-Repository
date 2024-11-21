Here is a translation of the Java code into equivalent Python:

```Python
import logging

class QuarkusAppStopMojo:
    def __init__(self):
        self.log = logging.getLogger(__name__)

    def execute(self) -> None:
        if self.is_skipped():
            self.log.info("Stopping Quarkus application.")
            return

        app = self.get_application()
        if app is None:
            self.log.warning(f"No application found for execution id '{self.execution_id}'.")
        
        try:
            app.close()
            self.log.info("Quarkus application stopped.")
        except Exception as e:
            raise Exception("Error while stopping Quarkus application", e)
        finally:
            self.reset_application()

    def is_skipped(self) -> bool:
        # Implement this method
        pass

    def get_execution_id(self) -> str:
        # Implement this method
        pass

    def reset_application(self):
        # Implement this method
        pass

    def get_application(self) -> object:
        # Implement this method
        pass
```

Please note that the above Python code is a translation of Java and does not include actual implementation for methods like `is_skipped`, `get_execution_id`, `reset_application` and `get_application`. These methods would need to be implemented based on your specific requirements.