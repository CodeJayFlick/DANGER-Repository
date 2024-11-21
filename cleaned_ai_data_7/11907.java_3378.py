class SettingsCache:
    CACHE_SIZE = 200

    class AddressNamePair:
        def __init__(self, address, name):
            self.address = address
            self.name = name

        def __eq__(self, other):
            if not isinstance(other, self.__class__):
                return False
            other_pair = other
            return (other_pair.address == self.address) and (other_pair.name == self.name)

        def __hash__(self):
            return hash((self.address, self.name))

    def __init__(self):
        from collections import OrderedDict
        self.map = OrderedDict()

    def remove(self, address, name):
        key = SettingsCache.AddressNamePair(address, name)
        if key in self.map:
            del self.map[key]

    def clear(self):
        self.map.clear()

    def get_instance_settings(self, address, name):
        key = SettingsCache.AddressNamePair(address, name)
        return self.map.get(key)

    def put(self, address, name, settings):
        key = SettingsCache.AddressNamePair(address, name)
        if key in self.map:
            del self.map[key]
        self.map[key] = settings
