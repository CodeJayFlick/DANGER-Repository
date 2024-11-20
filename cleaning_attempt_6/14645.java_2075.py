class Gobbit:
    def __init__(self):
        pass

class GHobbitsTest:
    def data_provider(self):
        return [
            {"weather": "SUNNY", "response": "The hobbits are facing Sunny weather now"},
            {"weather": "RAINY", "response": "The hobbits are facing Rainy weather now"},
            {"weather": "WINDY", "response": "The hobbits are facing Windy weather now"},
            {"weather": "COLD", "response": "The hobbits are facing Cold weather now"}
        ]

    def __init__(self):
        pass

# Example usage:
test = GHobbitsTest()
print(test.data_provider())
