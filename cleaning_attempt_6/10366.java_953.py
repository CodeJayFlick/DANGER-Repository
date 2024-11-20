class AbstractWeakValueNavigableMap:
    def __init__(self):
        pass

    class NavigableView:
        def __init__(self, map, mod):
            self.map = map
            self.mod = mod

        def get_ref_map(self):
            self.map.process_queue()
            return self.mod

    def process_queue(self):
        # TO DO: implement this method
        pass

    @property
    def ref_map(self):
        raise NotImplementedError("Must be implemented by subclass")

    def comparator(self):
        return self.ref_map.comparator()

    def first_key(self):
        self.process_queue()
        return self.ref_map.first_key()

    def last_key(self):
        self.process_queue()
        return self.ref_map.last_key()

    @staticmethod
    def generate_entry(ent):
        if ent is None:
            return None
        return GeneratedEntry(ent.key, ent.value.get())

    def lower_entry(self, key):
        self.process_queue()
        return self.generate_entry(self.ref_map.lower_entry(key))

    def lower_key(self, key):
        self.process_queue()
        return self.ref_map.lower_key(key)

    def floor_entry(self, key):
        self.process_queue()
        return self.generate_entry(self.ref_map.floor_entry(key))

    def floor_key(self, key):
        self.process_queue()
        return self.ref_map.floor_key(key)

    def ceiling_entry(self, key):
        self.process_queue()
        return self.generate_entry(self.ref_map.ceiling_entry(key))

    def ceiling_key(self, key):
        self.process_queue()
        return self.ref_map.ceiling_key(key)

    def higher_entry(self, key):
        self.process_queue()
        return self.generate_entry(self.ref_map.higher_entry(key))

    def higher_key(self, key):
        self.process_queue()
        return self.ref_map.higher_key(key)

    def first_entry(self):
        self.process_queue()
        return self.generate_entry(self.ref_map.first_entry())

    def last_entry(self):
        self.process_queue()
        return self.generate_entry(self.ref_map.last_entry())

    def poll_first_entry(self):
        self.process_queue()
        return self.generate_entry(self.ref_map.poll_first_entry())

    def poll_last_entry(self):
        self.process_queue()
        return self.generate_entry(self.ref_map.poll_last_entry())

    def descending_map(self):
        self.process_queue()
        return NavigableView(self, self.ref_map.descending_map())

    @property
    def navigable_key_set(self):
        raise NotImplementedError("Must be implemented by subclass")

    @property
    def descending_key_set(self):
        raise NotImplementedError("Must be implemented by subclass")

    def submap(self, from_key, from_inclusive, to_key, to_inclusive):
        self.process_queue()
        return NavigableView(self, self.ref_map.submap(from_key, from_inclusive, to_key, to_inclusive))

    def head_map(self, to_key, inclusive=False):
        self.process_queue()
        return NavigableView(self, self.ref_map.head_map(to_key, inclusive))

    def tail_map(self, from_key, inclusive=True):
        self.process_queue()
        return NavigableView(self, self.ref_map.tail_map(from_key, inclusive))

    def submap(self, from_key, to_key):
        return self.submap(from_key, True, to_key, False)

    def head_map(self, to_key):
        return self.head_map(to_key, False)

    def tail_map(self, from_key):
        return self.tail_map(from_key, True)
