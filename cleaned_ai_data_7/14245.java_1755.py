class SimpleProbabilisticThreatAwareSystem:
    def __init__(self, system_id: str, threats: list):
        self.system_id = system_id
        self.threats = threats

    @property
    def system_id(self) -> str:
        return self.system_id

    @property
    def threats(self) -> list:
        return self.threats

    def filtered(self) -> callable:
        return lambda predicate: SimpleProbabilisticThreatAwareSystem(
            self.system_id, 
            self.filtered_items(predicate)
        )

    def filtered_items(self, predicate):
        return [item for item in self.threats if predicate(item)]

# Example usage
system = SimpleProbabilisticThreatAwareSystem("my_system", ["threat1", "threat2", "threat3"])
print(system.system_id)  # prints: my_system
print(system.threats)     # prints: ['threat1', 'threat2', 'threat3']

predicate = lambda x: True if x == "threat1" else False
filtered_system = system.filtered()(predicate)
print(filtered_system.system_id)   # prints: my_system
print(filtered_system.threats)      # prints: ['threat1']
