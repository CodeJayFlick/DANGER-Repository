class SimpleThreatAwareSystem:
    def __init__(self, system_id: str, issues: list):
        self.system_id = system_id
        self.issues = issues

    @property
    def system_id(self) -> str:
        return self.system_id

    @property
    def threats(self) -> list:
        return self.issues[:]

    def filtered(self) -> Filterer:
        return lambda predicate: SimpleThreatAwareSystem(
            self.system_id, self.filtered_items(predicate)
        )

    def filtered_items(self, predicate):
        return [item for item in self.issues if predicate(item)]

class Threat:
    pass

# Example usage
system = SimpleThreatAwareSystem("my_system", ["threat1", "threat2", "threat3"])
print(system.system_id)  # Output: my_system
print(system.threats)  # Output: ['threat1', 'threat2', 'threat3']

filtered_system = system.filtered(lambda x: x.startswith("t"))
print(filtered_system.system_id)  # Output: my_system
print(filtered_system.threats)  # Output: ['threat1', 'threat2']
