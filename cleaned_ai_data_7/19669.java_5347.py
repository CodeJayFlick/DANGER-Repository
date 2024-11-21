class ReversedList:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        from skript import Skript
        Skript.register_expression(ReversedList, "reversed %objects%")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.list = exprs[0]
        return True

    @staticmethod
    def get(event):
        input_array = list(self.list.get(event))
        array = [None] * len(input_array)
        for i in range(len(array)):
            array[i] = input_array[len(array) - 1 - i]
        return array

    @staticmethod
    def reverse(array):
        left, right = 0, len(array) - 1
        while left < right:
            array[left], array[right] = array[right], array[left]
            left += 1
            right -= 1

    def is_single(self):
        return False

    @staticmethod
    def get_return_type():
        from skript import Skript
        return self.list.getReturnType()

    def __str__(self, event=None, debug=False):
        if not isinstance(event, dict) and not isinstance(debug, bool):
            raise TypeError("Invalid arguments")
        return f"reversed {self.list.__str__(event=event, debug=debug)}"
