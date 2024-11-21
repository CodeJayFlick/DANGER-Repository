class BullyMessageManagerTest:
    def test_send_heartbeat_message(self):
        instance1 = {"id": 1, "instance_id": 1}
        instance_map = {1: instance1}
        message_manager = self.BullyMessageManager(instance_map)
        assert message_manager.send_heartbeat_message(1)

    def test_send_election_message_not_accepted(self):
        try:
            instance1 = {"id": 1, "instance_id": 1}
            instance2 = {"id": 2, "instance_id": 2}
            instance3 = {"id": 3, "instance_id": 3}
            instance4 = {"id": 4, "instance_id": 4}
            instance_map = {1: instance1, 2: instance2, 3: instance3, 4: instance4}
            instance1["alive"] = False
            message_manager = self.BullyMessageManager(instance_map)
            result = message_manager.send_election_message(3, "3")
            expected_message = {"type": "ELECTION_INVOKE", "content": ""}
            assert ((instance2.get("message_queue")).pop()) == expected_message
            assert len((instance4.get("message_queue"))) == 0
            assert result is False

        except (AttributeError, KeyError):
            self.fail("Error to access private field.")

    def test_election_message_accepted(self):
        instance1 = {"id": 1, "instance_id": 1}
        instance2 = {"id": 2, "instance_id": 2}
        instance3 = {"id": 3, "instance_id": 3}
        instance4 = {"id": 4, "instance_id": 4}
        instance_map = {1: instance1, 2: instance2, 3: instance3, 4: instance4}
        instance1["alive"] = False
        message_manager = self.BullyMessageManager(instance_map)
        result = message_manager.send_election_message(2, "2")
        assert result is True

    def test_send_leader_message(self):
        try:
            instance1 = {"id": 1, "instance_id": 1}
            instance2 = {"id": 2, "instance_id": 2}
            instance3 = {"id": 3, "instance_id": 3}
            instance4 = {"id": 4, "instance_id": 4}
            instance_map = {1: instance1, 2: instance2, 3: instance3, 4: instance4}
            instance1["alive"] = False
            message_manager = self.BullyMessageManager(instance_map)
            message_manager.send_leader_message(2, 2)
            expected_message = {"type": "LEADER", "content": "2"}
            assert ((instance3.get("message_queue")).pop()) == expected_message
            assert ((instance4.get("message_queue")).pop()) == expected_message

        except (AttributeError, KeyError):
            self.fail("Error to access private field.")

    def test_send_heartbeat_invoke_message(self):
        try:
            instance1 = {"id": 1, "instance_id": 1}
            instance2 = {"id": 2, "instance_id": 2}
            instance3 = {"id": 3, "instance_id": 3}
            instance_map = {1: instance1, 2: instance2, 3: instance3}
            message_manager = self.BullyMessageManager(instance_map)
            message_manager.send_heartbeat_invoke_message(2)
            expected_message = {"type": "HEARTBEAT_INVOKE", "content": ""}
            assert ((instance3.get("message_queue")).pop()) == expected_message

        except (AttributeError, KeyError):
            self.fail("Error to access private field.")

class BullyMessageManager:
    def __init__(self, instance_map):
        self.instance_map = instance_map
        for key in self.instance_map.keys():
            self.instance_map[key]["message_queue"] = []

    def send_heartbeat_message(self, id):
        return True

    def send_election_message(self, id, content):
        if not self.instance_map.get(id)["alive"]:
            result = False
        else:
            result = True
        for key in self.instance_map.keys():
            message_queue = self.instance_map[key].get("message_queue")
            message_queue.append({"type": "ELECTION_INVOKE", "content": content})
        return result

    def send_leader_message(self, id, leader_id):
        for key in self.instance_map.keys():
            if key != id:
                instance = self.instance_map.get(key)
                instance["message_queue"].append({"type": "LEADER", "content": str(leader_id)})

    def send_heartbeat_invoke_message(self, id):
        message_queue = self.instance_map.get(id).get("message_queue")
        message_queue.append({"type": "HEARTBEAT_INVOKE", "content": ""})
