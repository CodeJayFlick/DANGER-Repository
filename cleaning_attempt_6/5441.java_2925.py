class AlignedObjectBasedPreviewTableModel:
    def __init__(self, model_name, provider, prog, monitor):
        self.alignment = 1
        self.filtered_indices = []
        self.alignment_listeners = set()

    def add_alignment_listener(self, alignment_listener):
        self.alignment_listeners.add(alignment_listener)

    def remove_alignment_listener(self, alignment_listener):
        self.alignment_listeners.remove(alignment_listener)

    @property
    def alignment(self):
        return self._alignment

    @alignment.setter
    def alignment(self, value):
        if value <= 0:
            raise ValueError("Alignment cannot be less than 1.")
        self._alignment = value
        self.re_filter()
        for listener in self.alignment_listeners:
            listener.alignment_changed()

    def re_filter(self):
        pass

    def do_filter(self, data, sorting_context, monitor):
        filtered_data = []
        for index, item in enumerate(data):
            address = self.get_alignment_address(item)
            if address.offset % self.alignment == 0:
                filtered_data.append(item)
        return super().do_filter(filtered_data, sorting_context, monitor)

    def do_load(self, accumulator, monitor):
        self.initialize_unaligned_list(accumulator, monitor)

    def initialize_unaligned_list(self, accumulator, monitor):
        pass

    def get_alignment_address(self, item):
        raise NotImplementedError("get_alignment_address must be implemented")

class Address:
    @property
    def offset(self):
        return 0

