Here's a translation of your Java code into Python:

```Python
class MemoryBytePatternSearcher:
    def __init__(self, search_name: str, pattern_list=None):
        self.search_name = search_name
        if pattern_list is None:
            self.pattern_list = []
        else:
            self.pattern_list = pattern_list

    def add_pattern(self, pattern):
        self.pattern_list.append(pattern)

    @property
    def do_executable_blocks_only(self) -> bool:
        return self._do_executable_blocks_only

    @do_executable_blocks_only.setter
    def do_executable_blocks_only(self, value: bool):
        self._do_executable_blocks_only = value

    def search(self, program, address_set_view=None, monitor=None):
        if not hasattr(self, 'root'):
            self.root = SequenceSearchState.build_state_machine(self.pattern_list)

        num_to_search = self.get_num_to_search(program)
        monitor.set_message(f"{self.search_name} Search")
        monitor.initialize(num_to_search)

        for block in program.memory.blocks:
            if not block.is_initialized():
                continue
            if self.do_executable_blocks_only and not block.is_execute():
                continue

            try:
                self.search_block(self.root, program, block, address_set_view, monitor)
            except IOException as e:
                print(f"Unable to scan block {block.name} for {self.search_name}")

        return num_to_search + len(program.memory.blocks)

    def get_num_to_search(self, program):
        num_addresses = 0
        for block in program.memory.blocks:
            if not block.is_initialized():
                continue
            if self.do_executable_blocks_only and not block.is_execute():
                continue

            num_addresses += block.size()

        return num_addresses

    def search_block(self, root_state: 'SequenceSearchState', program, block, address_set_view=None, monitor=None):
        done_set = AddressSet()
        for range in address_set_view:
            if address_set_view is None or not address_set_view.intersects(range.min_address(), range.max_address()):
                continue

            num_in_done_set = len(done_set)
            num_addresses_range = range.length()

            data = block.data
            stream_offset = 0
            max_block_search_length = min(block.size() - stream_offset, RESTRICTED_PATTERN_BYTE_RANGE + 1)

            for offset in range(stream_offset, max_block_search_length):
                root_state.apply(data.seek(offset), num_addresses_range, monitor=monitor)
                if monitor.check_canceled():
                    return

        return len(done_set) + block.size()

    def pre_match_apply(self, match_actions: list, addr: 'Address'):
        pass  # override in subclass

    def post_match_apply(self, match_actions: list, addr: 'Address'):
        pass  # override in subclass
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters. This is not strictly necessary for a working program, but it can be helpful for readability and maintainability.

I have also replaced Java's `IOException` with Python's built-in exception handling mechanism (`try/except`).