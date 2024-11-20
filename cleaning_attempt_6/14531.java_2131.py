class Star:
    def __init__(self, star_type: str, size: int, temperature: int):
        self.star_type = star_type
        self.size = size
        self.temperature = temperature

    def get_memento(self) -> 'StarMemento':
        return StarMemento(self)

    def time_passes(self):
        if self.star_type == "SUN":
            self.size -= 1000000
            self.temperature += 50000
        elif self.star_type == "RED_DWARF":
            self.size -= 2000000
            self.temperature -= 300000

    def set_memento(self, memento: 'StarMemento'):
        self.star_type = memento.get_star_type()
        self.size = memento.get_size()
        self.temperature = memento.get_temperature()

class StarMemento:
    def __init__(self, star):
        self.star_type = star.star_type
        self.size = star.size
        self.temperature = star.temperature

    def get_star_type(self) -> str:
        return self.star_type

    def get_size(self) -> int:
        return self.size

    def get_temperature(self) -> int:
        return self.temperature


def main():
    states = []

    star = Star("SUN", 10000000, 500000)
    print(star)
    states.append(StarMemento(star))
    star.time_passes()
    print(star)
    states.append(StarMemento(star))
    star.time_passes()
    print(star)
    states.append(StarMemento(star))
    star.time_passes()
    print(star)
    states.append(StarMemento(star))

    while len(states) > 0:
        memento = states.pop()
        star.set_memento(memento)
        print(star)


if __name__ == "__main__":
    main()

