Here is the equivalent Python code:

```Python
class StatusMemberTest:
    def test_status_records_the_start_time(self):
        from datetime import datetime
        start_time = datetime(2017, 4, 1, 19, 9)
        starting_data = {"started": start_time}
        status_member = StatusMember(1)

        status_member.accept(starting_data)
        self.assertEqual(status_member.get_started(), start_time)

    def test_status_records_the_stop_time(self):
        from datetime import datetime
        stop = datetime(2017, 4, 1, 19, 12)
        stopping_data = {"stopped": stop}
        data_bus = DataBus()
        status_member = StatusMember(1)

        status_member.accept(stopping_data)
        self.assertEqual(status_member.get_stopped(), stop)

    def test_status_ignores_message_data(self):
        message_data = "message"
        status_member = StatusMember(1)

        status_member.accept(message_data)
        self.assertIsNone(status_member.get_started())
        self.assertIsNone(status_member.get_stopped())

class DataBus:
    @classmethod
    def get_instance(cls):
        return cls()

class MessageData:
    def __init__(self, message):
        self.message = message

class StatusMember:
    def __init__(self, id):
        self.id = id
        self.started = None
        self.stopped = None

    def accept(self, data):
        if isinstance(data, dict) and "started" in data:
            self.started = data["started"]
        elif isinstance(data, dict) and "stopped" in data:
            self.stopped = data["stopped"]

    def get_started(self):
        return self.started

    def get_stopped(self):
        return self.stopped
```

Note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, you would typically write test cases as methods within a class that inherits from the built-in `unittest.TestCase`.