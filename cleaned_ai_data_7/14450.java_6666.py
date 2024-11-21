class AbstractMessageManager:
    def __init__(self, instance_map):
        self.instance_map = instance_map

    def find_next_instance(self, current_id):
        result = None
        candidate_list = sorted([k for k in self.instance_map if k > current_id and self.instance_map[k].is_alive()])
        if not candidate_list:
            index = min((k for k in self.instance_map if self.instance_map[k].is_alive()))
            result = self.instance_map[index]
        else:
            index = candidate_list[0]
            result = self.instance_map[index]
        return result

class Instance:
    def __init__(self):
        pass
    def is_alive(self):
        # implement your logic here to check if the instance is alive or not
        pass
