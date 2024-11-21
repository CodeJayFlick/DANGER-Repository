from typing import List

class AnchoredLayoutHandler:
    def __init__(self, model: object, view_height: int) -> None:
        self.model = model
        self.view_height = view_height
        self.layouts = []

    def position_layouts_around_anchor(self, anchor_index: int, view_position: int) -> List[object]:
        self.layouts.clear()

        layout = self.get_closest_layout(anchor_index, view_position)
        if layout is not None:
            self.layouts.append(layout)
            self.fill_out_layouts()
        
        return self.layouts[:]

    def shift_view_down_one_row(self) -> List[object]:
        if len(self.layouts) == 0:
            return []

        first = self.layouts[0]
        y_pos = first.get_ypos()
        scroll_amount = first.scrollable_unit_increment(-y_pos, 1)
        
        return self.shift_view(scroll_amount)

    def shift_view_up_one_row(self) -> List[object]:
        if len(self.layouts) == 0:
            return []

        last = self.layouts[-1]
        y_pos = last.get_ypos()
        scroll_amount = last.scrollable_unit_increment(-y_pos, -1)
        
        if y_pos == 0:
            layout = self.get_previous_layout(last.get_index(), y_pos)
            if layout is not None:
                self.layouts.insert(0, layout)
                y_pos = layout.get_ypos()

        return self.shift_view(scroll_amount)

    def shift_view_down_one_page(self) -> List[object]:
        if len(self.layouts) == 0:
            return []

        last = self.layouts[-1]
        diff = last.scrollable_unit_increment(self.view_height - last.get_ypos(), -1)
        
        return self.shift_view(self.view_height + diff)

    def shift_view_up_one_page(self) -> List[object]:
        if len(self.layouts) == 0:
            return []

        first = self.layouts[0]
        scroll_amount = self.view_height
        if first.get_ypos() != 0:
            diff = first.scrollable_unit_increment(-first.get_ypos(), 1)
            if diff < self.view_height:
                scroll_amount -= diff

        self.shift_view(-scroll_amount)

        return self.shift_view_down_one_row()

    def shift_view(self, view_amount: int) -> List[object]:
        self.reposition_layouts(view_amount)
        self.fill_out_layouts()
        
        return self.layouts[:]

    def set_view_height(self, new_height: int) -> List[object]:
        self.view_height = new_height
        if len(self.layouts) == 0:
            return self.position_layouts_around_anchor(0, 0)

        self.fill_out_layouts()

        return self.layouts[:]

    def fill_out_layouts(self):
        if len(self.layouts) == 0:
            return

        last = self.layouts[-1]
        y_pos = last.get_ypos() + last.get_height()
        
        while y_pos < self.view_height:
            next_layout = self.next_layout(last.get_index(), y_pos)
            if next_layout is not None:
                self.layouts.append(next_layout)
                y_pos += next_layout.get_height()
                last = next_layout
            else:
                break

        first = self.layouts[0]
        while first.get_ypos() > 0:
            prev_layout = self.previous_layout(first.get_index(), first.get_ypos())
            if prev_layout is not None:
                self.layouts.insert(0, prev_layout)
                first = prev_layout
            else:
                break

    def reposition_layouts(self, amount: int):
        for layout in self.layouts:
            layout.set_ypos(layout.get_ypos() + amount)

    def trim_layouts(self):
        it = iter(self.layouts)
        while True:
            try:
                layout = next(it)
                y_pos = layout.get_ypos()
                height = layout.get_height()

                if (y_pos + height <= 0) or (y_pos > self.view_height):
                    it.remove(layout)

            except StopIteration:
                break

    def fill_layouts_forward(self, existing_last_index: int, y: int):
        index = existing_last_index
        while y < self.view_height:
            next_layout = self.next_layout(index, y)
            if next_layout is not None:
                self.layouts.append(next_layout)
                y += next_layout.get_height()
                index = next_layout.get_index()
            else:
                break

    def fill_layouts_back(self, existing_first_index: int, y: int):
        index = existing_first_index
        while y > 0:
            prev_layout = self.previous_layout(index, y)
            if prev_layout is not None:
                self.layouts.insert(0, prev_layout)
                y -= prev_layout.get_height()
                index = prev_layout.get_index()
            else:
                break

    def get_previous_layout(self, index: int, y_pos: int) -> object:
        while (index := self.model.index_before(index)) is not None:
            layout = self.model.layout_at(index)
            if layout is not None:
                return AnchoredLayout(layout, index, y_pos - layout.get_height())

    def get_next_layout(self, index: int, y_pos: int) -> object:
        while (index := self.model.index_after(index)) is not None:
            layout = self.model.layout_at(index)
            if layout is not None:
                return AnchoredLayout(layout, index, y_pos)

    def get_closest_layout(self, index: int, y: int) -> object:
        layout = self.model.layout_at(index)
        if layout is not None:
            return AnchoredLayout(layout, index, y)

        next_layout = self.next_layout(index, y)
        if next_layout is not None:
            return next_layout

        prev_layout = self.previous_layout(index, y)
        if prev_layout is not None:
            prev_layout.set_ypos(y)
            return prev_layout

    def previous_layout(self, index: int, y_pos: int) -> object:
        while (index := self.model.index_before(index)) is not None:
            layout = self.model.layout_at(index)
            if layout is not None:
                return AnchoredLayout(layout, index, y_pos)

    def next_layout(self, index: int, y_pos: int) -> object:
        while (index := self.model.index_after(index)) is not None:
            layout = self.model.layout_at(index)
            if layout is not None:
                return AnchoredLayout(layout, index, y_pos)


class LayoutModel:
    def __init__(self):
        pass

    def get_layout(self, index: int) -> object:
        pass

    def get_index_before(self, index: int) -> int:
        pass

    def get_index_after(self, index: int) -> int:
        pass


class AnchoredLayout:
    def __init__(self, layout: object, index: int, y_pos: int):
        self.layout = layout
        self.index = index
        self.ypos = y_pos

    def set_ypos(self, ypos: int):
        self.ypos = ypos

    def get_ypos(self) -> int:
        return self.ypos

    def scrollable_unit_increment(self, amount: int, direction: int) -> int:
        pass


class Layout:
    def __init__(self):
        pass

    def get_height(self) -> int:
        pass
