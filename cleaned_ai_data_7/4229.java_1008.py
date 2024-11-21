class DraggableScriptTable:
    def __init__(self, provider: 'GhidraScriptComponentProvider', model):
        self.provider = provider
        super().__init__(model)
        self.init_drag_ndrop()

    def init_drag_ndrop(self):
        # set up drag stuff
        pass  # implement this method

    def is_start_drag_ok(self, e):
        return True

    def get_drag_source_listener(self):
        return self.drag_source_adapter

    def get_drag_action(self):
        return DnDConstants.ACTION_COPY_OR_MOVE

    def get_transferable(self, p: 'Point'):
        selected_rows = self.get_selected_rows()
        array_list = []
        for row in selected_rows:
            array_list.append(self.provider.get_script_at(row))
        return GhidraTransferable(array_list)

    def move(self):
        pass  # implement this method

    def drag_canceled(self, event: 'DragSourceDropEvent'):
        pass  # implement this method


class DragSrcAdapter:
    def __init__(self, table: 'DraggableScriptTable'):
        self.table = table

    def get_drag_source_listener(self):
        return self


class GhidraTransferable:
    def __init__(self, array_list):
        self.array_list = array_list
