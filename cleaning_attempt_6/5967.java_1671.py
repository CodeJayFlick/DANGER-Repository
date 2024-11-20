import threading

class GhidraThreadedTablePanel:
    def __init__(self, model):
        super().__init__(model)

    def __init__(self, model, min_update_delay):
        super().__init__(model, min_update_delay)

    def __init__(self, model, min_update_delay, max_update_delay):
        super().__init__(model, min_update_delay, max_update_delay)

    def create_table(self, model):
        return GhidraTable(model)

    def get_table(self):
        return self.super_get_table()

class GhidraTable:
    pass
