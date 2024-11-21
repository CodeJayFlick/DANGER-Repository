class BullyinstanceTest:
    def test_on_message(self):
        try:
            bully_instance = BullyInstance(None, 1, 1)
            bully_message = Message(MessageType.HEARTBEAT, "")
            bully_instance.on_message(bully_message)
            instance_class = type(AbstractInstance())
            message_queue_field = getattr(instance_class, "messageQueue")
            self.assertEqual(bully_message, message_queue_field.get(0))
        except (AttributeError, TypeError):
            self.fail("Failed to access message queue.")

    def test_is_alive(self):
        try:
            bully_instance = BullyInstance(None, 1, 1)
            instance_class = type(AbstractInstance())
            alive_field = getattr(instance_class, "alive")
            alive_field.set(bully_instance, False)
            self.assertFalse(bully_instance.is_alive())
        except (AttributeError, TypeError):
            self.fail("Failed to access field 'alive'.")

    def test_set_alive(self):
        bully_instance = BullyInstance(None, 1, 1)
        bully_instance.set_alive(False)
        self.assertFalse(bully_instance.is_alive())

class Message:
    def __init__(self, message_type: str, content: str):
        self.message_type = message_type
        self.content = content

class MessageType(str):
    HEARTBEAT = "HEARTBEAT"

class BullyInstance:
    def on_message(self, message):
        pass

    def is_alive(self) -> bool:
        return True

    def set_alive(self, alive: bool):
        pass
