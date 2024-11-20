class StickToTopLinearLayoutManager:
    def __init__(self):
        pass  # No direct equivalent in Python for Context parameter.

    def on_items_added(self, recyclerView, positionStart, itemCount):
        super().on_items_added(recyclerView, positionStart, itemCount)
        if positionStart == 0 and self.find_first_completely_visible_item_position() <= itemCount:
            self.scrollToPosition(0)

class LinearLayoutManager:
    pass

# No direct equivalent in Python for the following Java classes.
class RecyclerView:
    def __init__(self):
        pass
