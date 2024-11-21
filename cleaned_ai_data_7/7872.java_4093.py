class MDMangGenericize:
    def __init__(self):
        self.genericized_string = StringBuilder()
        self.unique_count = -1
        self.next_unique = self.next_unique()
        self.unique_fragments = {}

    def demangle(self, error_on_remaining_chars=False) -> 'MDParsableItem':
        if not self.mangled:
            raise MDException("MDMang: Mangled string is null.")
        
        self.push_context()
        item = MDMangObjectParser.parse(self)
        num_chars_remaining = len(iter.get_string()) - iter.get_index()
        self.append_remainder()
        self.pop_context()

        if error_on_remaining_chars and num_chars_remaining > 0:
            raise MDException("MDMang: characters remain after demangling: " + str(num_chars_remaining) + ".")

        return item

    def next(self):
        return super().next()

    def get_and_increment(self):
        c = self.next()
        self.genericized_string.append(c)
        return c

    def increment(self, count=1):
        for _ in range(count):
            c = self.get_and_increment()
            self.genericized_string.append(c)

    def next_unique(self) -> str:
        self.unique_count += 1
        return "name" + str(self.unique_count)

    def create_and_append_generic_fragment(self, fragment: str):
        if not fragment:
            return

        if fragment[0] == 'A':
            self.next_unique = 'A' + self.next_unique()

        unique_fragment = self.unique_fragments.get(fragment)
        if unique_fragment is None:
            unique_fragment = self.next_unique
            self.next_unique = self.next_unique()
        
        self.genericized_string.append(unique_fragment)

    def append_remainder(self):
        if iter.get_index() < len(iter.get_string()):
            self.genericized_string.append(iter.get_string()[iter.get_index():])

    @property
    def generic_symbol(self) -> str:
        return self.genericized_string.toString()

class MDParsableItem:
    pass

class MDException(Exception):
    pass
