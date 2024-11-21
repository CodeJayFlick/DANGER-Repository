class Address:
    def __init__(self):
        pass

class ProgramDB:
    def get_image_base(self):
        return "default image base"

    def set_image_base(self, addr, update=False):
        if not update:
            raise IllegalStateException("Cannot change the image base without updating")

class SetBaseCommand:
    def __init__(self, addr):
        self.addr = addr
        self.msg = None

    def apply_to(self, obj):
        p = ProgramDB()
        try:
            p.set_image_base(addr=True)
        except (IllegalStateException, AddressOverflowException) as e:
            self.msg = str(e)
            return False
        except LockException as e:
            self.msg = "Must have exclusive checkout to set the image base"
            return False
        return True

    def get_status_msg(self):
        return self.msg if self.msg else ""

    def get_name(self):
        return "Set Image Base"

class ImageBaseDialog:
    def __init__(self, tool, program, current_addr):
        super().__init__()
        self.program = program
        self.current_addr = current_addr
        self.tool = tool

    def dispose(self):
        self.close()
        self.tool = None
        self.program = None

    def create_work_panel(self):
        panel = JPanel(MiddleLayout())
        text_field = JTextField(20)
        text_field.setText(str(current_addr))
        text_field.selectAll()
        text_field.addActionListener(lambda e: ok_callback())

        document_listener = DocumentListener()
        text_field.getDocument().addDocumentListener(document_listener)

        panel.add(text_field)
        return panel

    def update_address(self):
        clear_status_text()
        addr_string = self.text_field.get_text()
        try:
            addr = ProgramDB().get_image_base(addr_string)
        except AddressFormatException as e:
            pass
        if not addr:
            set_status_text("Invalid Address")
        else:
            set_ok_enabled(True)

    def ok_callback(self):
        if self.addr and self.addr != current_addr:
            msg.info(self, f"old base = {self.program.get_image_base()}")
            command = SetBaseCommand(addr)
            if not self.tool.execute(command, self.program):
                set_status_text(command.get_status_msg())
                return
            msg.info(self, f"new base = {self.program.get_image_base()}")
        close()

class JPanel:
    def __init__(self, layout):
        pass

def clear_status_text():
    pass

def set_ok_enabled(enabled):
    pass

def set_status_text(text):
    pass

def msg_info(obj, text):
    print(f"{obj}: {text}")

def msg(obj, text):
    print(f"{obj}: {text}")
