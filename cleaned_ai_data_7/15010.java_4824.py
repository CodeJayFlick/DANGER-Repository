class ColorSelector:
    def __init__(self, target_color):
        self.target_color = target_color

    def test(self, creature):
        return creature.color == self.target_color


def test_color():
    green_creature = {"color": "GREEN"}
    red_creature = {"color": "RED"}

    green_selector = ColorSelector("GREEN")
    assert green_selector.test(green_creature) is True
    assert green_selector.test(red_creature) is False


if __name__ == "__main__":
    test_color()
