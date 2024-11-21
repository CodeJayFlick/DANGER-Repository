Here is the translation of the Java code to Python:

```Python
import logging

class UserUpdatedEventHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def on_event(self, event: dict) -> None:
        user_username = event.get('user', {}).get('username')
        if user_username is not None:
            self.logger.info("User '{}' has been Updated!".format(user_username))
```

Note that Python does not have direct equivalent of Java's `Slf4j` or `Handler`. The above code uses Python's built-in logging module to achieve similar functionality.