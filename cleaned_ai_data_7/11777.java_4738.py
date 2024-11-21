class SectionVector:
    def __init__(self, rtl, scope):
        self.next_index = -1
        self.main_pair = {"section": rtl, "scope": scope}
        self.named_pairs = []

    @property
    def main_section(self):
        return self.main_pair["section"]

    def get_named_section(self, index):
        return self.named_pairs[index]["section"]

    @property
    def main_pair(self):
        return self.main_pair

    def get_named_pair(self, i):
        return self.named_pairs[i]

    def set_next_index(self, i):
        self.next_index = i

    @property
    def max_id(self):
        return len(self.named_pairs)

    def append(self, rtl, scope):
        while len(self.named_pairs) <= self.next_index:
            self.named_pairs.append({"section": None, "scope": None})
        self.named_pairs[self.next_index] = {"section": rtl, "scope": scope}
