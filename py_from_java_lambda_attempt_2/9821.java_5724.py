Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class GTableHeaderRenderer:
    def __init__(self):
        self.textLabel = tk.Label()
        self.iconLabel = tk.Label()
        self.helpIcon = None
        self.customBorder = CustomPaddingBorder()

    @property
    def isPaintingPrimarySortColumn(self):
        return self._isPaintingPrimarySortColumn

    @isPaintingPrimarySortColumn.setter
    def isPaintingPrimarySortColumn(self, value):
        self._isPaintingPrimarySortColumn = value

    def paintChildren(self, g):
        super().paintChildren(g)
        self.paintHelpIcon(g)

    def paintHelpIcon(self, g):
        if not self.helpIcon:
            return
        point = self.getHelpIconLocation()
        self.helpIcon.place(x=point[0], y=point[1])

    def getHelpIconLocation(self):
        primary_width = self.iconLabel.winfo_reqwidth()
        overlay_width = self.helpIcon.width

        paint_point = (primary_width - overlay_width, 0)
        return paint_point

    @property
    def foreground(self):
        return self._foreground

    @foreground.setter
    def foreground(self, value):
        self._foreground = value

    @property
    def font(self):
        return self._font

    @font.setter
    def font(self, value):
        self._font = value

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        self.isPaintingPrimarySortColumn = False  # reset
        icon = None
        text = str(value) if value else ""

        header = table.heading(column)
        self.foreground = header.cget("foreground")
        self.font = header.cget("font")

        model_index = table.convert_column_to_model(column)
        model = table.model

        icon = self.getIcon(model, model_index)

        variable_model = VariableColumnTableModel.from_(model)
        if variable_model:
            text = variable_model.column_display_name(model_index)
        else:
            text = str(value) if value else ""

        self.updateHelpIcon(table, column, icon)
        self.iconLabel.config(text="", image=icon)
        self.textLabel.config(text=text)

        self.setOuterBorder(self.customBorder, column)

    def getIcon(self, model, columnModelIndex):
        icon = None
        if isinstance(model, SortedTableModel):
            icon = self.getSortIcon(icon, columnModelIndex, model)
        elif isColumnFiltered(model, columnModelIndex):
            icon = combineIcons(icon, FILTER_ICON)
        return icon

    def combineIcons(self, icon1, icon2):
        if not icon1:
            return icon2
        if not icon2:
            return icon1
        multi_icon = MultiIcon(EmptyIcon(28, 14))
        multi_icon.add_icon(icon2)
        multi_icon.add_icon(TranslateIcon(icon1, 14, 0))
        return multi_icon

    def isColumnFiltered(self, model, columnModelIndex):
        if not isinstance(model, RowObjectFilterModel):
            return False
        filter_model = RowObjectFilterModel.from_(model)
        table_filter = filter_model.table_filter
        if not table_filter:
            return False
        return table_filter.has_column_filter(columnModelIndex)

    def setOuterBorder(self, border, column):
        if self.paintAquaHeaders():
            if column == 0:
                self.customBorder.set_outer_border(NoSidesLineBorder(Color.GRAY))
            else:
                self.customBorder.set_outer_border(NoRightSideLineBorder(Color.GRAY))
        else:
            self.customBorder.set_outer_border(UIManager.get("TableHeader.cellBorder"))

    def paintComponent(self, g):
        g2d = tk.Canvas.create_window(g)
        backgroundColor = self.background_paint()
        oldPaint = g2d.cget("paint")
        g2d.config("paint", backgroundColor)
        g2d.fill(0, 0, self.winfo_width(), self.winfo_height())
        g2d.config("paint", oldPaint)

    def getBackgroundPaint(self):
        if self.isPaintingPrimarySortColumn:
            return GradientPaint(0, 0, PRIMARY_SORT_GRADIENT_START, 0, self.winfo_height() - 11,
                                  PRIMARY_SORT_GRADIENT_END)
        else:
            return GradientPaint(0, 0, DEFAULT_GRADIENT_START, 0, self.winfo_height() - 11,
                                  DEFAULT_GRADIENT_END)

    def updateHelpIcon(self, table, current_column_index, icon):
        header = table.heading(current_column_index)
        if not isinstance(header, GTableHeader):
            return
        tooltip_header = GTableHeader.from_(header)
        hovered_column_index = tooltip_header.hovered_header_column_index
        if hovered_column_index != current_column_index:
            self.helpIcon = None
            return

    def getSortIcon(self, icon, realIndex, model):
        sorted_model = SortedTableModel.from_(model)
        column_sort_states = sorted_model.table_sort_state
        sort_pending = False
        if isinstance(model, AbstractSortedTableModel):
            abstract_sorted_model = AbstractSortedTableModel.from_(model)
            sort_pending = abstract_sorted_model.is_sort_pending()
            if sort_pending:
                pending_table_state = abstract_sorted_model.pending_sort_state
                column_sort_state = pending_table_state.column_sort_state(realIndex)
                return self.getIconForSortState(column_sort_states, column_sort_state, True)

        column_sort_state = column_sort_states.column_sort_state(realIndex)
        icon = self.getIconForSortState(column_sort_states, column_sort_state, False)
        if sort_pending:
            # indicate that the current sort is stale
            return ResourceManager.disabled_icon(icon, 65)

    def getIconForSortState(self, column_sort_states, sort_state, pending):
        icon = UP_ICON if sort_state.is_ascending else DOWN_ICON

        if column_sort_states.get_sorted_column_count() != 1:
            multi_icon = MultiIcon(EmptyIcon(28, 14))
            multi_icon.add_icon(icon)
            order_string = str(sort_state.order_order())
            multi_icon.add_icon(NumberPainterIcon(icon.width + PADDING_FOR_COLUMN_NUMBER,
                                                   icon.height, order_string))

        return icon

    def isSortedAscending(self):
        return self.iconLabel.cget("image") == UP_ICON


class CustomPaddingBorder:
    def __init__(self):
        self.inside_border = createOSSpecificBorder()
        self.outside_border = None

    def set_outer_border(self, border):
        self.outside_border = border
```

Please note that the translation is not a direct copy-paste from Java to Python. It's more of an interpretation and adaptation of the code into Python syntax.

The following are some key differences:

1.  **Indentation**: In Python, indentation (spaces or tabs) is used to denote block-level structure.
2.  **Class Definition**: Classes in Python start with `class` followed by the class name.
3.  **Method Definition**: Methods in Python use the `def` keyword and are indented under their respective classes.
4.  **Variable Declaration**: Variables in Python do not need explicit declaration, but they must be assigned a value before being used.
5.  **Conditional Statements**: Conditional statements (if-else) in Python follow the same syntax as Java, with some minor differences in indentation and parentheses usage.
6.  **Loops**: Loops (for/while) in Python use similar syntax to Java, but with different indentation rules.

This code should be run within a Tkinter environment or using PIL library for image processing.