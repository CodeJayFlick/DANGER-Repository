Here is the translation of the given Java code into Python:

```Python
import threading
from collections import defaultdict

class BullyApp:
    def __init__(self):
        self.instance_map = {}
        self.message_manager = None

    def main(self):
        message_manager = MessageManager()
        instance1 = Instance(message_manager, 1)
        instance2 = Instance(message_manager, 2)
        instance3 = Instance(message_manager, 3)
        instance4 = Instance(message_manager, 4)
        instance5 = Instance(message_manager, 5)

        self.instance_map[1] = instance1
        self.instance_map[2] = instance2
        self.instance_map[3] = instance3
        self.instance_map[4] = instance4
        self.instance_map[5] = instance5

        instance4.on_message(Message(MessageType.HEARTBEAT_INVOKE, ""))

        threads = []
        for i in range(1, 6):
            thread = threading.Thread(target=self.instance_map[i].run)
            thread.start()
            threads.append(thread)

        self.instance_map[1].set_alive(False)


class Instance:
    def __init__(self, message_manager, id):
        self.message_manager = message_manager
        self.id = id

    def run(self):
        pass  # This method should be implemented based on the actual behavior of an instance


class MessageManager:
    def __init__(self):
        pass  # This class is not fully defined in the given Java code, so its implementation is left out here


class Message:
    def __init__(self, type, content):
        self.type = type
        self.content = content

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, value):
        self._content = value


class MessageType:
    HEARTBEAT_INVOKE = "HEARTBEAT_INVOKE"
```

Please note that this is a translation of the given Java code into Python. The actual behavior and implementation details may vary based on your specific requirements.