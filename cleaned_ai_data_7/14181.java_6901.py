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
