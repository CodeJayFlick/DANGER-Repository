class MessageCollectorMemberTest:
    def test_collect_message_from_message_data(self):
        message = "message"
        message_data = {"type": "MessageData", "data": message}
        collector = MessageCollectorMember("collector")
        
        # when
        collector.accept(message_data)
        
        # then
        self.assertTrue(message in collector.messages)

    def test_collect_ignores_message_from_other_data_types(self):
        starting_data = {"type": "StartingData"}
        collector = MessageCollectorMember("collector")

        # when
        collector.accept(starting_data)

        # then
        self.assertEqual(0, len(collector.messages))

class MessageCollectorMember:
    def __init__(self, name):
        self.name = name
        self.messages = []

    def accept(self, data):
        if isinstance(data, dict) and "type" in data and data["type"] == "MessageData":
            self.messages.append(data["data"])
