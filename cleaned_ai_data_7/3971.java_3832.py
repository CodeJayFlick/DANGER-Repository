class EndianFlipWidget:
    def __init__(self, title, parent):
        self.parent = parent
        super().__init__()

    def create_content(self):
        main_panel = JPanel()
        flip_endianness_btn = JButton("flip")
        main_panel.add(flip_endianness_btn)
        flip_endianness_btn.addActionListener(EndianFlipper())

        return main_panel

class EndianFlipper:
    def __init__(self, parent):
        self.parent = parent

    def actionPerformed(self, event):
        groups = self.parent.get_input_string().strip().split()
        whitespaces = InstructionSearchUtils.get_whitespace(self.parent.get_input_string().strip())
        
        for group in groups:
            if not self.parent.validate_input(group):
                self.parent.show_error()
                return
        
        byte_length = 0
        input_mode = self.parent.selection_mode_widget.input_mode
        if input_mode == "HEX":
            byte_length = 2
        elif input_mode == "BINARY":
            byte_length = 8

        if len(groups) != len(whitespaces) + 1:
            return
        
        main_string = ""
        whitespace_index = 0
        for group in groups:
            bytes_list = get_byte_strings(group, byte_length)
            bytes_list.reverse()
            
            for s in bytes_list:
                main_string += s
            
            if whitespace_index < len(whitespaces):
                main_string += whitespaces[whitespace_index]
                whitespace_index += 1
        
        self.parent.set_input_string(main_string)

def get_byte_strings(token, byte_length):
    n = len(token) // byte_length
    list_ = []
    
    for i in range(n):
        list_.append(token[i * byte_length:i * byte_length + byte_length])
        
    return list_

class InstructionSearchUtils:
    @staticmethod
    def get_whitespace(input_string):
        # implement this method as per your requirement

def main():
    parent = InsertBytesWidget()
    
    widget = EndianFlipWidget("Endian Flip", parent)
    content = widget.create_content()

if __name__ == "__main__":
    main()
