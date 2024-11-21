from collections import defaultdict, OrderedDict

class Delta:
    EMPTY = Delta({}, {})

    def __init__(self, removed: dict, added: dict):
        self.removed = removed
        self.added = added

    @staticmethod
    def create(removed_keys: list, added: dict) -> 'Delta':
        return Delta({k: None for k in removed_keys}, added)

    @staticmethod
    def compute_and_set(mutable: dict, desired: dict, equals=None):
        if not equals:
            equals = lambda a, b: a == b

        removed = defaultdict(dict)
        added = OrderedDict()

        retain_keys(mutable, set(desired.keys()), removed)
        put_entries(mutable, desired, removed, added, equals)

        return Delta(removed, added)

    @staticmethod
    def apply(mutable: dict, removed_keys: list, added: dict, equals=None):
        if not equals:
            equals = lambda a, b: a == b

        f_removed = defaultdict(dict)
        f_added = OrderedDict()

        remove_keys(mutable, removed_keys, f_removed)

        put_entries(mutable, added, f_removed, f_added, equals)

        return Delta(f_removed, f_added)

    @staticmethod
    def apply_to_keys(mutable: dict, removed_keys: list, added: dict):
        mutable.update(added)
        mutable.difference_update(removed_keys)


def retain_keys(mutable: dict, keys: set, removed: dict):
    for key in mutable:
        if key not in keys:
            removed[key] = mutable.pop(key)


def put_entries(mutable: dict, entries: dict, removed: dict, added: OrderedDict, equals=None):
    for entry_key, value in entries.items():
        new_value = value
        old_value = mutable.get(entry_key)
        if old_value and not equals(old_value, new_value):
            removed[entry_key] = old_value
            added[entry_key] = new_value


def remove_keys(mutable: dict, keys: list, f_removed: defaultdict):
    for key in keys:
        if key in mutable:
            f_removed[key] = mutable.pop(key)
