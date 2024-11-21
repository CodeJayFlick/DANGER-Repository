class FVSliderUI:
    def __init__(self, slider, scrollPane, table, reader, model):
        self.slider = slider
        self.scrollPane = scrollPane
        self.table = table
        self.reader = reader
        self.model = model

    def calculateThumbSize(self):
        super().calculateThumbSize()

        try:
            file_size = self.reader.get_file_size()
        except Exception as e:
            print(f"Error reading file size: {e}")
            return

        rows = self.table.rowcount
        if rows == 0:
            return

        bytes_in_view = 0
        for chunk in self.model:
            bytes_in_view += (chunk.end - chunk.start)

        bytes_per_line = bytes_in_view / rows
        total_lines_in_file = file_size // bytes_per_line

        viewable_ratio = scrollPane.get_viewport().height / total_lines_in_file
        thumb_height = viewable_ratio * self.table.row_height
        if thumb_height < 20:
            thumb_height = 20
        elif thumb_height > 1000:  # adjust this value as needed
            thumb_height = 1000

        self.thumb_rect.size = (10, int(thumb_height))
