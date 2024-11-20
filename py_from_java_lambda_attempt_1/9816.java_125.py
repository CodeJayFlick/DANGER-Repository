Here is the translation of the Java code into Python:

```Python
class GTableCellRenderer:
    INTEGER_ RADIX_SETTING = "DECIMAL"
    FLOATING_POINT_PRECISION_SETTING = 10

    def __init__(self):
        self.font = None

    def get_text(self, value):
        if value is None:
            return ""
        else:
            return str(value)

    def format_number(self, value, settings):
        number_string = str(value)
        
        if isinstance(value, (int, long)):
            radix = INTEGER_RADIX_SETTING
            sign_mode = "DEF"
            
            number_string = NumericUtilities.format_number(number_string, radix, sign_mode)
            
        elif isinstance(value, float) or isinstance(value, (float, 'float')):
            digits_precision = FLOATING_POINT_PRECISION_SETTING
            
            if math.isnan(value) or math.isinf(value):
                return "\u221e"  # infinity symbol
            else:
                number_string = "{:.{}f}".format(value, str(digits_precision).zfill(10))
                
        elif isinstance(value, (int, long)):
            radix = INTEGER_RADIX_SETTING
            
            number_string = str(BigInteger(str(value)).toString(radix))
            
        elif isinstance(value, float) or isinstance(value, (float, 'float')):
            number_string = str(BigDecimal(str(value)).toPlainString())
        
        return number_string

    def get_table_cell_renderer_component(self, data):
        value = data.get_value()
        table = data.get_table()
        row = data.get_row_view_index()
        column = data.get_column_view_index()
        selected = data.is_selected()
        has_focus = data.has_focus()
        settings = data.get_settings()

        if isinstance(value, (int, long)):
            self.set_horizontal_alignment(SwingConstants.RIGHT)
            self.set_text(self.format_number(value, settings))
            
        else:
            self.set_text(self.get_text(value))
            self.set_horizontal_alignment(SwingConstants.LEFT)

        table_model = table.get_model()
        
        if selected:
            self.set_foreground(table.get_selection_foreground())
            self.set_background_color(table.get_selection_background_color())
            self.set_opacity(True)
        else:
            self.set_foreground_color(table, table_model, value)

            if row == drop_row:
                self.set_background_color(Color.CYAN)
            else:
                self.set_background_color(self.get_os_dependent_background_color(table, row))

        self.set_border(has_focus and focus_border or noFocusBorder)
        
        return self

    def set_foreground_color(self, table, model, value):
        self.set_foreground(table.get_foreground())

    def configure_font(self, table, model, column):
        self.set_font(defaultFont)

    def get_formatter(self, digits_precision):
        if not hasattr(self, 'decimal_format_cache'):
            self.init_format_cache()

        return self.decimal_format_cache[digits_precision]

    def init_format_cache(self):
        self.decimal_format_cache = {}
        
        for i in range(FloatingPointPrecisionSettingsDefinition.MAX_PRECISION + 1):
            self.decimal_format_cache[i] = DecimalFormat("0." + "0" * (i - 1))

class GTableCellRenderingData:
    def __init__(self, table, row_view_index, column_view_index, value, selected, has_focus, settings):
        self.table = table
        self.row_view_index = row_view_index
        self.column_view_index = column_view_index
        self.value = value
        self.selected = selected
        self.has_focus = has_focus
        self.settings = settings

    def get_value(self):
        return self.value

    def get_table(self):
        return self.table

    def get_row_view_index(self):
        return self.row_view_index

    def get_column_view_index(self):
        return self.column_view_index

    def is_selected(self):
        return self.selected

    def has_focus(self):
        return self.has_focus

    def get_settings(self):
        return self.settings
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. The above code uses the `String` class for formatting numbers, which may behave differently than in Java.