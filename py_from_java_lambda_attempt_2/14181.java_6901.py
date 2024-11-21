Here is the equivalent Python code:

```Python
import logging
from unittest import TestCase

class CommanderTest(TestCase):

    def test_commander_ready(self):
        commander_logger = logging.getLogger('Commander')
        commander_logger.setLevel(logging.INFO)

        list_appender = logging.handlers.ListHandler()
        appender_handler = logging.StreamHandler(list_appender)
        commander_logger.addHandler(appender_handler)

        unit_name = "CommanderUnitTest"
        commander = Commander(CommanderUnit(unit_name))
        commander.commander_ready()

        logs_list = [event.getMessage() for event in list_appender.get_messages()]
        self.assertEqual(f"[Commander] {unit_name} is ready!", logs_list[0])
```

Note that Python's logging module does not have a direct equivalent to Java's Logback. However, the above code uses Python's built-in `logging` module and its handlers (in this case, the `ListHandler`) to achieve similar functionality.

Also note that there are some differences in how exceptions are handled between Java and Python. In particular, Python does not have a direct equivalent to JUnit tests like those used in the original code.