import unittest
from ghidra_framework import ProjectTestUtils, ToolManager


class ConnectToolsTest(unittest.TestCase):

    BAD_EVENT_NAME = "TEST_CONNECT_FOR_BAD_EVENT"
    DIRECTORY_NAME = AbstractGTest.get_test_directory_path()
    PROJECT_NAME = ""

    def setUp(self):
        ProjectTestUtils.delete_project(DIRECTORY_NAME, self.PROJECT_NAME)
        project = ProjectTestUtils.get_project(DIRECTORY_NAME, self.PROJECT_NAME)

    def tearDown(self):
        project.close()
        ProjectTestUtils.delete_project(DIRECTORY_NAME, self.PROJECT_NAME)


class ConnectTools(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.project = ProjectTestUtils. delete_project(DIRECTORY_NAME, PROJECT_ NAME)
        cls.producer = DummyTool("ProducerTool")
        cls.consumer = DummyTool("ConsumerTool")

    @classmethod
    def tearDownClass(cls):
        cls.project.close()
        ProjectTestUtils.delete_project(DIRECTORY_NAME, self.PROJECT_NAME)

    def test_connect_tools(self):

        tool_manager = project.get_tool_manager()

        producer_event_names = self.producer.get_tool_event_names()
        consumer_consumed_names = self.consumer.get_consumed_tool_event_names()

        if not (producer_event_names and consumer_consumed_names):
            self.fail("Connect Tools Failed: no event names for connection")

        good_event_name = can_connect_tools(producer_event_names, consumer_consumed_names)

        tool_connection = tool_manager.get_connection(self.producer, self.consumer)
        tool_connection.connect(good_event_name)
        if not tool_connection.is_connected(good_event_name):
            self.fail("Connect Tools Failed: {} and {} failed to CONNECT for event {}".format(
                producer.name(), consumer.name(), good_event_name))

        try:
            tool_connection.connect(self.BAD_EVENT_NAME)
        except Exception as e:
            pass

        if tool_connection.is_connected(self.BAD_EVENT_NAME):
            self.fail("Connect Tools Failed: {} and {} connected for BAD EVENT".format(producer.name(),
                                                                                        consumer.name()))

        # disconnect the tools
        tool_connection.disconnect(good_event_name)

        if tool_connection.is_connected(good_event_name):
            self.fail("Connect Tools Failed: {} and {} failed to DISCONNECT for event {}".format(
                producer.name(), consumer.name(), good_event_name))


    def can_connect_tools(self, event_names, consumed_names):

        for event in event_names:
            for name in consumed_names:
                if event == name:
                    return event
        return None


if __name__ == "__main__":
    unittest.main()
