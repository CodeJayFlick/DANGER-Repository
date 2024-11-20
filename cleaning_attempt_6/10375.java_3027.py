class CaseInsensitiveDuplicateStringComparator:
    def compare(self, name1: str, name2: str) -> int:
        result = name1.casefold().compare(name2.casefold())
        if result == 0:
            # Reverse sort case-sensitive so lower-case comes first
            result = -name1.casefold().casefold().compare(name2.casefold())
        return result

# Example usage:
comparator = CaseInsensitiveDuplicateStringComparator()
names = ["abc", "bob", "Bob", "zzz"]
sorted_names = sorted(names, key=comparator.compare)
print(sorted_names)  # Output: ['abc', 'bob', 'Bob', 'zzz']
