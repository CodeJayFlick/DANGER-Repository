class HalflingThief:
    def __init__(self, method):
        self.method = method

    def steal(self):
        print("Stealing...")
        self.method.hit_and_run()
        print("Done stealing...")

    def change_method(self, new_method):
        self.method = new_method


class HitAndRunMethod:
    def hit_and_run(self):
        print("Hitting and running...")


class SubtleMethod:
    def hit_and_run(self):
        print("Stealing subtly...")


def main():
    thief = HalflingThief(HitAndRunMethod())
    thief.steal()
    thief.change_method(SubtleMethod())
    thief.steal()


if __name__ == "__main__":
    main()
