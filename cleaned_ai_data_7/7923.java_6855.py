class MDVCall:
    NEAR_STRING = "__near"
    FAR_STRING = "__far"

    class ThisModel(enum.Enum):
        NEAR = 1
        FAR = 2

    class CallModel(enum.Enum):
        NEAR = 1
        FAR = 2

    class VfptrModel(enum.Enum):
        NEAR = 1
        FAR = 2
        BASED = 3

    def __init__(self, dmang):
        super().__init__()
        self.mdtype = MDFunctionType(dmang, False, False)
        # TODO: consider what to do... from what I understand, this is
        # also "virtual" but "virtual" does not get printed.
        self.set_thunk()
        self.call_index = MDEncodedNumber(dmang)

    def insert(self, builder):
        super().insert(builder)

    @property
    def name_modifier_16_bit_model(self):
        modifier = f"{{ {self.call_index}, "
        if self.my_this_model == MDVCall.ThisModel.NEAR:
            modifier += MDVCall.NEAR_STRING
        else:
            modifier += MDVCall.FAR_STRING
        modifier += "this, "
        if self.my_call_model == MDVCall.CallModel.NEAR:
            modifier += MDVCall.NEAR_STRING
        else:
            modifier += MDVCall.FAR_STRING
        modifier += "call, "
        if self.my_vfptr_model == MDVCall.VfptrModel.NEAR:
            modifier += MDVCall.NEAR_STRING
        elif self.my_vfptr_model == MDVCall.VfptrModel.FAR:
            modifier += MDVCall.FAR_STRING
        else:
            modifier += str(self.based_type)
        return f"}}' }'"

    @property
    def name_modifier_32_plus_bit_model(self):
        if (self.my_this_model == MDVCall.ThisModel.NEAR and 
                self.my_call_model == MDVCall.CallModel.NEAR and 
                self.my_vfptr_model == MDVCall.VfptrModel.NEAR):
            return f"{{ {self.call_index}, {{flat}}' }'}"
        else:
            return ""

    def parse_internal(self):
        self.call_index.parse()
        self.thunk_type = dmang.get_and_increment()
        if self.thunk_type in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']:
            if self.thunk_type == 'A':
                self.my_this_model = MDVCall.ThisModel.NEAR
                self.my_call_model = MDVCall.CallModel.NEAR
                self.my_vfptr_model = MDVCall.VfptrModel.NEAR
            elif self.thunk_type == 'B':
                self.my_this_model = MDVCall.ThisModel.NEAR
                self.my_call_model = MDVCall.CallModel.FAR
                self.my_vfptr_model = MDVCall.VfptrModel.NEAR
            # ... and so on for the rest of the cases

        elif self.thunk_type == 'I':
            self.my_this_model = MDVCall.ThisModel.NEAR
            self.my_call_model = MDVCall.CallModel.NEAR
            self.my_vfptr_model = MDVCall.VfptrModel.BASED
            self.based_type.parse()
        # ... and so on for the rest of the cases

        else:
            raise MDException(f"VCall ({self.thunk_type}), unexpected thunkType")

        super().parse_internal()

    name_modifier = property(get_name_modifier_32_plus_bit_model)

class MDEncodedNumber:
    def __init__(self, dmang):
        pass
    def parse(self):
        pass

class MDFunctionType:
    def __init__(self, dmang, is_virtual, is_pure):
        self.dmang = dmang
        self.is_virtual = is_virtual
        self.is_pure = is_pure

class MDBasedAttribute:
    def __init__(self):
        pass
