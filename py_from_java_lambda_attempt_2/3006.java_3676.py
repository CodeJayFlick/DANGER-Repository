Here is the translation of the given Java code into Python:

```Python
import ghidra_app_script_gcc_arm as GhidraScript

class CreateStringScript(GhidraScript):
    TERMINATOR = b'\n'

    def run(self):
        addr = self.find(None, self.TERMINATOR)
        while addr is not None:
            self.create_string(addr)
            try:
                addr = addr.add(1).addNoWrap()
                addr = self.find(addr, self.TERMINATOR)
            except AddressOverflowException as e:
                # must be at largest possible address - so we are done
                pass

    def create_string(self, end_addr):
        start_addr = self.find_start_of_string(end_addr)
        length = (end_addr - start_addr) + 1
        if length < 4:
            print(f"Too small, Skipping {start_addr}")
            return
        try:
            self.my_create_ascii_string(start_addr, length)
            self.create_label_for_string(start_addr, length)
        except Exception as e:
            print(f"error creating string at {end_addr}. Reason: {e.message}")

    def my_create_ascii_string(self, start_addr, length):
        data = self.current_program.get_listing().create_data(start_addr, new StringDataType(), length)

    def find_start_of_string(self, end_addr):
        addr = end_addr
        start_addr = end_addr
        while True:
            try:
                addr -= 1
                if not self.is_ascii_and_not_terminator(addr):
                    return start_addr
            except AddressOverflowException as e:
                # TODO Auto-generated catch block
                pass

    def is_ascii_and_not_terminator(self, addr):
        try:
            b = self.current_program.get_memory().get_byte(addr)
            if b == self.TERMINATOR:
                return False
            return 0x20 <= ord(b) <= 0x7f or b in [b'\n', b'\r', b'\t']
        except MemoryAccessException as e:
            return False

    def create_label_for_string(self, addr, length):
        listing = self.current_program.get_listing()
        memory = self.current_program.get_memory()
        data = listing.get_data_at(addr)
        value = str(data.get_value())
        if not value:
            return
        needs_underscore = True
        buf = StringBuffer()
        bytes = bytearray(length)
        try:
            memory.get_bytes(addr, bytes)
        except MemoryAccessException as e:
            pass
        for i in range(length):
            c = chr(bytes[i])
            if 0x20 <= ord(c) <= 0x7f:
                if needs_underscore:
                    buf.append('_')
                    needs_underscore = False
                else:
                    buf.append(c)
            elif c != 0:
                needs_underscore = True
        new_label = str(buf)

        self.create_label(addr, new_label, True)
```

Please note that Python does not have direct equivalent of Java's `GhidraScript` class. The above code is a translation of the given Java code into Python and it may require some modifications to work correctly in your specific environment.