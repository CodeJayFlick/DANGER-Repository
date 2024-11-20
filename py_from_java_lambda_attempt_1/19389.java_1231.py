Here is the translation of the Java code into Python:

```Python
class EffToggle:
    def __init__(self):
        self.blocks = None
        self.toggle = -1

    @staticmethod
    def register_effect():
        Skript.register_effect(EffToggle, "(close|turn off|de[-]activate) %blocks%", "(toggle|switch) [[the] state of] %blocks%", "(open|turn on|activate) %blocks%")

    @staticmethod
    def get_data_method():
        try:
            return MethodHandles.lookup().findVirtual(Block, "setData", MethodType.method_type(void))
        except (NoSuchMethodException, IllegalAccessException):
            return None

    def init(self, vars, matched_pattern, is_delayed, parse_result):
        self.blocks = vars[0]
        self.toggle = matched_pattern - 1
        return True

    # Used for Minecraft 1.12 and older
    bit_flags = [0] * (Skript.MAXBLOCKID + 1)
    doors = [False] * (Skript.MAXBLOCKID + 1)

    @staticmethod
    def init_legacy():
        self.bit_flags[28] = 8  # Detector rail
        # Doors
        self.bit_flags[64] = 4  # Oak door (block)
        self.bit_flags[193] = 4  # Spruce door (block)
        self.bit_flags[194] = 4  # Birch door (block)
        self.bit_flags[195] = 4  # Jungle door (block)
        self.bit_flags[196] = 4  # Acacia door (block)
        self.bit_flags[197] = 4  # Dark oak door (block)
        self.bit_flags[71] = 4  # Iron door (block)

    def execute(self, e):
        if not flattening:
            self.execute_legacy(e)
            return

        for block in self.blocks.get_array(e):
            data = block.block_data
            if self.toggle == -1:
                if isinstance(data, Openable):
                    ((Openable) data).set_open(False)
                elif isinstance(data, Powerable):
                    ((Powerable) data).set_powered(False)
            elif self.toggle == 1:
                if isinstance(data, Openable):
                    ((Openable) data).set_open(True)
                elif isinstance(data, Powerable):
                    ((Powerable) data).set_powered(True)
            else:
                if isinstance(data, Openable):  # open = NOT was open
                    ((Openable) data).set_open(not ((Openable) data).is_open())
                elif isinstance(data, Powerable):  # power = NOT power
                    ((Powerable) data).set_powered(not ((Powerable) data).is_powered())

            block.set_block_data(data)

    def execute_legacy(self, e):
        for block in self.blocks.get_array(e):
            type_id = block.type.id

            if doors[type_id] and (block.data & 0x8) == 0x8:
                block = block.relative(BlockFace.DOWN)
                type_id = block.type.id
                if not doors[type_id]:
                    continue
                data = block.data

            method_handle = self.get_data_method()
            assert method_handle is not None, "MethodHandle should be defined"
            try:
                if self.toggle == -1:
                    method_handle.invoke_exact(block, (data & ~self.bit_flags[type_id]))
                elif self.toggle == 0:
                    method_handle.invoke_exact(block, data ^ self.bit_flags[type_id])
                else:
                    method_handle.invoke_exact(block, data | self.bit_flags[type_id])
            except Exception as ex:
                Skript.exception(ex)

    def __str__(self, e=None, debug=False):
        return "toggle " + str(self.blocks)
```

Note that this code is not a direct translation of the Java code. It's more like an interpretation in Python style.