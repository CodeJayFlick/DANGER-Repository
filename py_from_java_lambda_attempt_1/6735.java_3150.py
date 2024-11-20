Here is the translation of the Java code into Python:

```Python
class FieldFactory:
    def __init__(self, model, bytes_per_line, field_offset, font_metrics):
        self.model = model
        self.field_offset = field_offset
        self.font_metrics = font_metrics
        self.char_width = font_metrics.get_char_width('W')
        self.width = self.char_width * self.model.data_unit_symbol_size()
        self.edit_color = ByteViewerComponentProvider.DEFAULT_EDIT_COLOR
        self.separator_color = ByteViewerComponentProvider.DEFAULT_MISSING_VALUE_COLOR
        self.unit_byte_size = self.model.unit_byte_size

    def set_start_x(self, x):
        self.start_x = x

    def get_start_x(self):
        return self.start_x

    def get_field(self, index):
        if not hasattr(self, 'index_map'):
            return None
        
        info = self.index_map.get_block_info(index, self.field_offset)
        
        if info is None:
            if self.index_map.show_separator(index):
                bf = ByteField('?', self.font_metrics, self.start_x, self.width, False, self.field_offset, index, HighlightFactory())
                bf.set_foreground(self.separator_color)
                return bf
            else:
                return None
        
        try:
            block = info.get_block()
            offset = info.get_offset()

            if not block.has_value(offset):
                # if the ByteBlock doesn't have initialized values at the offset, don't try to read
                # as it causes visual slowness when exceptions are thrown and caught.
                return self.get_byte_field('?', index)
            
            str_val = self.model.data_representation(block, offset)
            bf = ByteField(str_val, self.font_metrics, self.start_x, self.width, False, self.field_offset, index, HighlightFactory())
            if block_set.is_changed(block, offset, unit_byte_size):
                bf.set_foreground(self.edit_color)
            
            return bf
        except (ByteBlockAccessException, AddressOutOfBoundsException, IndexOutOfBoundsException) as e:
            # usually caused by uninitialized memory block
            return self.get_byte_field('?', index)

    def get_width(self):
        return self.width

    def get_metrics(self):
        return self.font_metrics


class ByteField:
    def __init__(self, value, font_metrics, start_x, width, editable, field_offset, index, highlight_factory):
        self.value = value
        self.font_metrics = font_metrics
        self.start_x = start_x
        self.width = width
        self.editable = editable
        self.field_offset = field_offset
        self.index = index
        self.highlight_factory = highlight_factory

    def set_foreground(self, color):
        pass


class HighlightFactory:
    def __init__(self, provider):
        self.provider = provider

    def get_highlights(self, text, cursor_text_offset):
        return self.provider.get_highlights(text, None, None, -1)


# usage
model = DataFormatModel()
bytes_per_line = 10
field_offset = 5
font_metrics = FontMetrics()

factory = FieldFactory(model, bytes_per_line, field_offset, font_metrics)
```

Please note that this is a direct translation of the Java code into Python. The original Java code seems to be part of an application for visualizing and editing binary data, so you may need additional classes or functions depending on your specific use case.

Also, I've omitted some parts of the code as they are not directly translatable (e.g., `ByteBlockSet`, `IndexMap`), assuming that these will be implemented elsewhere in your Python application.