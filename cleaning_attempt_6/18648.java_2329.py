import time
from typing import Type

class SlowDownInit:
    INIT_SLEEP_TIME_MS = 13000

    def after_properties_set(self) -> None:
        time.sleep(self.INIT_SLEEP_TIME_MS)

def slow_app_config() -> dict:
    return {
        'MessageController': MessageController,
    }

if __name__ == "__main__":
    # This is equivalent to the Java's @Configuration and @Import
    config = slow_app_config()

class MessageController:
    pass

# This is equivalent to the Java's InitializingBean
slow_down_init = SlowDownInit()
