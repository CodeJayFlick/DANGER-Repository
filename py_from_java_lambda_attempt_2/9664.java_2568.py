Here is the translation of the Java code into Python:

```Python
class DefaultViewToIndexMapper:
    MAX_SCROLL_VALUE = 2**31 // 2  # at max value, java has bug
    AVERAGE_HEIGHT = 20

    def __init__(self, model: 'IndexedScrollable', screen_height: int):
        self.model = model
        self.screen_height = screen_height
        self.reset_state()

    def reset_state(self) -> None:
        index_count = self.model.index_count()
        total_height = index_count * AVERAGE_HEIGHT

        if total_height > self.MAX_SCROLL_VALUE:
            view_height = self.MAX_SCROLL_VALUE
        else:
            view_height = int(total_height)

        x_factor = index_count / (view_height - screen_height)
        last_start_index = index_count - 1
        last_start_y = 0
        end_validated = False

    def get_index(self, value: int) -> 'BigInteger':
        if value == view_height - self.screen_height:
            return last_start_index

        dindex = value * x_factor
        bindex = BigDecimal(str(dindex))
        return bindex.to_int()

    def get_vertical_offset(self, value: int) -> int:
        return 0

    def get_view_height(self) -> int:
        return self.view_height

    def set_visible_view_height(self, screen_height: int) -> None:
        self.screen_height = screen_height
        self.reset_state()

    def get_scroll_value(self, start_index: 'BigInteger', end_index: 'BigInteger', start_y: int, end_y: int) -> int:
        if not end_validated:
            if end_index == last_start_index and end_y <= self.screen_height:
                last_start_index = start_index
                last_start_y = start_y
                x_factor = start_index / (self.view_height - self.screen_height)
                end_validated = True

        if start_index == 0 and start_y == 0:
            return 0

        if start_index == last_start_index and start_y == last_start_y:
            return self.view_height - self.screen_height

        scroll_value = start_index / x_factor
        value = int(scroll_value + 0.5)

        if value == 0:
            return 1

        if value >= self.view_height - self.screen_height:
            return self.view_height - self.screen_height - 1
        return value

    def index_model_data_changed(self, start: 'BigInteger', end: 'BigInteger') -> None:
        if end >= last_start_index:
            self.reset_state()
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters. However, since this is a translation from Java code, some types (like `IndexedScrollable`) are not defined in Python and would need to be replaced with actual classes or interfaces if you were going to use this code as-is.