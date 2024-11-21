class ListenerSet:
    CALLING_THREAD = None

    def __init__(self, iface):
        self.map = ListenerMap(iface)
        self.fire = self.map.fire

    @classmethod
    def create_map(cls):
        return CacheBuilder().weak_keys().weak_values().concurrency_level(1).build()

class ListenerMap:
    CALLING_THREAD = None

    def __init__(self, iface):
        self.iface = iface
        self.executor = ListenerSet.CALLING_THREAD
        self.map = cls.create_map()
        self.fire = self.map['fire']

    @classmethod
    def create_map(cls):
        return {}

    def notify_removed(self, rn):
        pass

class CacheBuilder:
    @staticmethod
    def new_builder():
        return {'weak_keys': True, 'weak_values': True, 'concurrency_level': 1}

def main():
    # Usage example
    listener_set = ListenerSet('com.example.MyInterface')
    print(listener_set.fire)

if __name__ == "__main__":
    main()
