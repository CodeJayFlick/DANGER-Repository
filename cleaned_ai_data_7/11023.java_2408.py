import collections

class TransientDataManager:
    __init__ = lambda self: None  # equivalent to private constructor in Java

    _set = set()  # equivalent to CopyOnWriteArraySet<DomainFileProxy> in Java

    @classmethod
    def add_transient(cls, domain_file):
        cls._set.add(domain_file)

    @classmethod
    def remove_transient(cls, domain_file):
        cls._set.remove(domain_file)

    @classmethod
    def clear_all(cls):
        cls._set.clear()

    @classmethod
    def get_transients(cls, l: list) -> None:
        l.extend(list(cls._set))

    @classmethod
    def release_files(cls, consumer: object) -> None:
        for df in cls._set:
            df.release(consumer)
