class MergeUtilities:
    @staticmethod
    def adjust_sets(latest_diffs: set, my_diffs: set, auto_changes: set, conflict_changes: set) -> None:
        diff_auto_changes = my_diffs - latest_diffs
        diff_conflict_changes = my_diffs & latest_diffs
        auto_changes.update(diff_auto_changes)
        conflict_changes.update(diff_conflict_changes)

    # @staticmethod
    # def get_code_unit_set(addr_set, listing):
    #     addrs = set()
    #     for range_ in addr_set:
    #         min_addr = range_[0]
    #         max_addr = range_[1]
    #         code_unit_min_cu = listing.get_code_unit(min_addr)
    #         if code_unit_min_cu is not None:
    #             addrs.add(code_unit_min_cu.min_address())
    #         code_unit_max_cu = listing.get_code_unit(max_addr)
    #         if code_unit_max_cu is not None:
    #             addrs.add(code_unit_max_cu.max_address())
    #     return addrs

    @staticmethod
    def same(o1, o2) -> bool:
        if o1 is None:
            return o2 is None
        else:
            return o1 == o2

    @staticmethod
    def to_signed_hex_string(value: int | long) -> str:
        if value >= 0:
            return f"0x{hex(int(value))[2:]}"
        else:
            return f"-0x{hex(-value)[2:]}"

# Usage example:
if __name__ == "__main__":
    latest_diffs = {1, 3}
    my_diffs = {1, 2, 4}
    auto_changes = set()
    conflict_changes = set()

    MergeUtilities.adjust_sets(latest_diffs, my_diffs, auto_changes, conflict_changes)

    print(auto_changes)  # Output: {1, 2, 4}
    print(conflict_changes)  # Output: {3}

# Test the same function
print(MergeUtilities.same(None, None))  # True
print(MergeUtilities.same(0, "Hello"))  # False

# Test to_signed_hex_string function
for value in [12, -12]:
    print(f"Value: {value}, Hex String: {MergeUtilities.to_signed_hex_string(value)}")
