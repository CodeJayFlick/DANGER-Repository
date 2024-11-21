import io

class IExternalSortFileSerializer:
    def write(self, time_value_pair: 'TimeValuePair') -> None:
        # TO DO: implement writing logic
        pass

    def close(self) -> None:
        # TO DO: implement closing logic
        pass


# Note: TimeValuePair is not a built-in Python type,
# so you would need to define it or use an equivalent data structure.
