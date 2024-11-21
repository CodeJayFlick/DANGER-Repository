class FixedTracker:
    def __init__(self, value):
        self.value = value

    @property
    def new_value(self):
        return self.value


def fixed_tracker_builder(value=None):
    tracker = FixedTracker(value)
    return tracker


if __name__ == "__main__":
    builder = fixed_tracker_builder(10.0)  # create a builder with initial value of 10.0
    print(builder.new_value)  # prints: 10.0

