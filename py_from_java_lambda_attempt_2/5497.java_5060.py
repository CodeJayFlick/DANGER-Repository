Here is the translation of the Java code into Python:

```Python
class ListingTextField:
    def __init__(self, factory: 'FieldFactory', proxy: 'ProxyObj[?]'):
        self.factory = factory
        self.proxy = proxy
        self.field = None

    @staticmethod
    def create_single_line_text_field(factory: 'FieldFactory', 
                                       proxy: 'ProxyObj[?]', 
                                       field_element: object, 
                                       start_x: int, 
                                       width: int, 
                                       provider: 'HighlightProvider') -> 'ListingTextField':
        hl_factory = FieldHighlightFactory(provider, factory.__class__, proxy.get_object())
        text_field = ClippingTextField(start_x, width, field_element, hl_factory)
        return ListingTextField(factory, proxy, text_field)

    @staticmethod
    def create_single_line_text_field_with_reverse_clipping(factory: 'FieldFactory', 
                                                            proxy: 'ProxyObj[?]', 
                                                            field_element: object, 
                                                            start_x: int, 
                                                            width: int, 
                                                            provider: 'HighlightProvider') -> 'ListingTextField':
        hl_factory = FieldHighlightFactory(provider, factory.__class__, proxy.get_object())
        text_field = ReverseClippingTextField(start_x, width, field_element, hl_factory)
        return ListingTextField(factory, proxy, text_field)

    @staticmethod
    def create_word_wrapped_text_field(factory: 'FieldFactory', 
                                       proxy: 'ProxyObj[?]', 
                                       field_element: object, 
                                       start_x: int, 
                                       width: int, 
                                       max_lines: int, 
                                       provider: 'HighlightProvider') -> 'ListingTextField':
        hl_factory = FieldHighlightFactory(provider, factory.__class__, proxy.get_object())
        text_field = WrappingVerticalLayoutTextField(field_element, start_x, width, max_lines, hl_factory)
        return ListingTextField(factory, proxy, text_field)

    @staticmethod
    def create_packed_text_field(factory: 'FieldFactory', 
                                 proxy: 'ProxyObj[?]', 
                                 field_elements: list, 
                                 start_x: int, 
                                 width: int, 
                                 max_lines: int, 
                                 provider: 'HighlightProvider') -> 'ListingTextField':
        hl_factory = FieldHighlightFactory(provider, factory.__class__, proxy.get_object())
        text_field = FlowLayoutTextField(field_elements, start_x, width, max_lines, hl_factory)
        return ListingTextField(factory, proxy, text_field)

    @staticmethod
    def create_multiline_text_field(factory: 'FieldFactory', 
                                    proxy: 'ProxyObj[?]', 
                                    field_elements: list, 
                                    start_x: int, 
                                    width: int, 
                                    max_lines: int, 
                                    provider: 'HighlightProvider') -> 'ListingTextField':
        hl_factory = FieldHighlightFactory(provider, factory.__class__, proxy.get_object())
        text_field = VerticalLayoutTextField(field_elements, start_x, width, max_lines, hl_factory)
        return ListingTextField(factory, proxy, text_field)

    def set_primary(self, b: bool):
        self.field.set_primary(b)

    def data_to_screen_location(self, row: int, col: int) -> 'RowColLocation':
        return self.field.data_to_screen_location(row, col)

    def screen_to_data_location(self, screen_row: int, screen_column: int) -> 'RowColLocation':
        return self.field.screen_to_data_location(screen_row, screen_column)

    @property
    def width(self):
        return self.field.width

    @property
    def preferred_width(self):
        return self.field.preferred_width

    @property
    def height(self):
        return self.field.height

    @property
    def height_above(self):
        return self.field.height_above

    @property
    def height_below(self):
        return self.field.height_below

    @property
    def start_x(self):
        return self.field.start_x

    def paint(self, c: object, g: 'Graphics', context: 'PaintContext', 
              clip: 'Rectangle', map: 'FieldBackgroundColorManager', cursor_loc: 'RowColLocation', row_height: int) -> None:
        self.field.paint(c, g, context, clip, map, cursor_loc, row_height)

    def contains(self, x: int, y: int):
        return self.field.contains(x, y)

    @property
    def num_data_rows(self):
        return self.field.num_data_rows

    @property
    def num_rows(self):
        return self.field.num_rows

    @property
    def num_cols(self, row: int) -> int:
        return self.field.num_cols(row)

    @property
    def x(self, row: int, col: int) -> int:
        return self.field.x(row, col)

    @property
    def y(self, row: int) -> int:
        return self.field.y(row)

    @property
    def row(self, y: int) -> int:
        return self.field.row(y)

    @property
    def col(self, row: int, x: int) -> int:
        return self.field.col(row, x)

    def is_valid(self, row: int, col: int):
        return self.field.is_valid(row, col)

    def cursor_bounds(self, row: int, col: int) -> 'Rectangle':
        return self.field.cursor_bounds(row, col)

    @property
    def scrollable_unit_increment(self, top_of_screen: int, direction: int, max: int) -> int:
        return self.field.scrollable_unit_increment(top_of_screen, direction, max)

    @property
    def is_primary(self):
        return self.field.is_primary

    def row_height_changed(self, height_above: int, height_below: int) -> None:
        self.field.row_height_changed(height_above, height_below)

    def get_text(self) -> str:
        return self.field.get_text()

    def get_text_with_line_separators(self) -> str:
        return self.field.get_text_with_line_separators()

    @property
    def text_offset_to_screen_location(self, text_offset: int):
        return self.field.text_offset_to_screen_location(text_offset)

    @property
    def screen_location_to_text_offset(self, row: int, col: int) -> int:
        return self.field.screen_location_to_text_offset(row, col)

    @property
    def field_factory(self):
        return self.factory

    def __str__(self):
        return self.get_text()

    @property
    def proxy(self):
        if not self.proxy:
            return EmptyProxy.EMPTY_PROXY
        return self.proxy

    @property
    def field_model(self) -> 'FieldFormatModel':
        return self.factory.field_model

    @property
    def is_clipped(self):
        return self.field.is_clipped()

    def get_clicked_object(self, location: 'FieldLocation') -> object:
        return self.get_field_element(location.row, location.col)

    def get_field_element(self, screen_row: int, screen_column: int) -> object:
        return self.field.get_field_element(screen_row, screen_column)
```

Note that I've replaced the Java-specific types (e.g. `FieldFactory`, `ProxyObj[?]`) with Python-style type hints (`'FieldFactory'`, `'ProxyObj[?]'`). This is not strictly necessary for the code to work, but it can help catch type-related errors at runtime or during static analysis.