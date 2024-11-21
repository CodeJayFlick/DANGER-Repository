class Trigger:
    def __init__(self):
        pass

    def on_create(self, attributes: dict) -> None:
        """Called when trigger is created."""
        pass

    def on_drop(self) -> None:
        """Called when trigger is dropped."""
        pass

    def on_start(self) -> None:
        """Called when trigger starts firing."""
        pass

    def on_stop(self) -> None:
        """Called when trigger stops firing."""
        pass

    def fire_scalar_value(self, timestamp: int, value):
        return value

    def fire_array_values(self, timestamps: list[int], values):
        for i in range(len(timestamps)):
            self.fire_scalar_value(timestamps[i], values[i])
        return values

    def fire_float_value(self, timestamp: float, value) -> float:
        return value

    def fire_float_array_values(self, timestamps: list[float], values):
        for i in range(len(timestamps)):
            self.fire_float_value(timestamps[i], values[i])
        return values

    def fire_double_value(self, timestamp: float, value) -> float:
        return value

    def fire_double_array_values(self, timestamps: list[float], values):
        for i in range(len(timestamps)):
            self.fire_double_value(timestamps[i], values[i])
        return values

    def fire_bool_value(self, timestamp: int, value) -> bool:
        return value

    def fire_bool_array_values(self, timestamps: list[int], values):
        for i in range(len(timestamps)):
            self.fire_bool_value(timestamps[i], values[i])
        return values

    def fire_binary_value(self, timestamp: int, value) -> Binary:
        return value

    def fire_binary_array_values(self, timestamps: list[int], values):
        for i in range(len(timestamps)):
            self.fire_binary_value(timestamps[i], values[i])
        return values
