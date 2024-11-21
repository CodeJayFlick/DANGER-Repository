class ByteSequenceLengthFilterInputDialog:
    def __init__(self, title):
        self.index_box = None
        self.min_length_box = None
        self.ok_button_text = "Apply"
        self.cancel_button_text = "Cancel"

    def create_panel(self):
        main_panel = tkinter.Frame()
        pair_layout = tkinter.PairLayout()
        main_panel.pack(fill="both", expand=True)
        main_panel.grid_columnconfigure(0, weight=1)

        label_index_box_title = tkinter.Label(main_panel, text="Prefix Length in Bytes (Negative for Suffix):")
        label_index_box_title.grid(row=0, column=0, sticky=tkinter.W+tkinter.E)

        self.index_box = tkinter.Entry(main_panel)
        self.index_box.grid(row=1, column=0, sticky=tkinter.W+tkinter.E)

        label_length_box_title = tkinter.Label(main_panel, text="Minimum Length in Bytes of String:")
        label_length_box_title.grid(row=2, column=0, sticky=tkinter.W+tkinter.E)

        self.min_length_box = tkinter.Entry(main_panel)
        self.min_length_box.grid(row=3, column=0, sticky=tkinter.W+tkinter.E)

    def get_value(self):
        index = int(self.index_box.get())
        min_length = int(self.min_length_box.get())

        if index > min_length:
            return None

        try:
            return ByteSequenceLengthFilter(index, min_length)
        except Exception as e:
            print(f"Error: {e}")
            return None


class ByteSequenceLengthFilter:
    def __init__(self, index, min_length):
        self.index = index
        self.min_length = min_length

