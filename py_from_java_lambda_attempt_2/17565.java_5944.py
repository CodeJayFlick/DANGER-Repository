Here is the translation of the Java code to Python:

```Python
class SafetyLine:
    INITIAL_PILE_POSITION = -1

    def __init__(self):
        self.safety_piles = [0] * 8
        self.size = 0

    def get_safety_line(self):
        min_value = self.safety_piles[0]
        for i in range(1, self.size):
            min_value = min(min_value, self.safety_piles[i])
        return min_value

    def add_safety_pile(self):
        if self.size < len(self.safety_piles):
            self.safety_piles[self.size] = self.INITIAL_PILE_POSITION
            return SafetyPile(self.size)
        else:
            new_safety_piles = [0] * (len(self.safety_piles) << 1)
            for i in range(len(self.safety_piles)):
                new_safety_piles[i] = self.safety_piles[i]
            self.safety_piles = new_safety_piles
        return SafetyPile(self.size)

    class SafetyPile:
        def __init__(self, safety_pile_index):
            self.safety_pile_index = safety_pile_index

        def move_forward_to(self, safety_pile_position):
            self.safety_piles[self.safety_pile_index] = safety_pile_position


class ElasticSerializableTVList:
    pass
```

Note that I did not translate the `ElasticSerializableTVList` class as it was empty in the original Java code.