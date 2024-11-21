class ConstTpl:
    REAL = 0
    HANDLE = 1
    J_START = 2
    J_NEXT = 3
    J_CURSPACE = 4
    J_CURSPACE_SIZE = 5
    SPACEID = 6
    J_RELATIVE = 7
    J_FLOWREF = 8
    J_FLOWREF_SIZE = 9
    J_FLOWDEST = 10
    J_FLOWDEST_SIZE = 11

    V_SPACE = 0
    V_OFFSET = 1
    V_SIZE = 2
    V_OFFSET_PLUS = 3

    calc_mask = [0, 0xffL, 0xffffL, 0xffffffL, 0xffffffffL,
                 0xffffffffffL, 0xffffffffffffL, 0xffffffffffffffL, 0xffffffffffffffffL]

    def __init__(self):
        self.type = ConstTpl.REAL
        self.value_real = 0

    def __init__(self, op2):
        self.type = op2.type
        self.value_real = op2.value_real
        self.value_spaceid = op2.value_spaceid
        self.handle_index = op2.handle_index
        self.select = op2.select

    def __init__(self, tp, val):
        self.type = tp
        self.value_real = val

    def __init__(self, tp):
        self.type = tp

    def __init__(self, spc):
        self.type = ConstTpl.SPACEID
        self.value_spaceid = spc

    def __init__(self, tp, ht, vf):
        self.type = ConstTpl.HANDLE
        self.handle_index = ht
        self.select = vf

    def is_const_space(self):
        if self.type == ConstTpl.SPACEID:
            return self.value_spaceid.get_type() == 1
        return False

    def is_unique_space(self):
        if self.type == ConstTpl.SPACEID:
            return self.value_spaceid.get_type() == 2
        return False

    def get_real(self):
        return self.value_real

    def get_space_id(self):
        return self.value_spaceid

    def get_handle_index(self):
        return self.handle_index

    def get_type(self):
        return self.type

    def fix(self, walker):
        if self.type == ConstTpl.J_START:
            return walker.get_addr().get_offset()
        elif self.type == ConstTpl.J_NEXT:
            return walker.get_naddr().get_offset()
        elif self.type in [ConstTpl.J_FLOWREF, ConstTpl.J_FLOWDEST]:
            return walker.get_flow_ref_addr().get_offset()
        elif self.type in [ConstTpl.J_CURSPACE, ConstTpl.J_CURSPACE_SIZE]:
            return walker.get_cur_space().get_pointer_size()
        elif self.type == ConstTpl.HANDLE:
            fixed_hand = walker.get_fixed_handle(self.handle_index)
            if self.select == ConstTpl.V_SPACE:
                if fixed_hand.offset_space is None:
                    return fixed_hand.space.get_space_id()
                else:
                    return fixed_hand.temp_space.get_space_id()
            elif self.select in [ConstTpl.V_OFFSET, ConstTpl.V_SIZE]:
                return fixed_hand.size
            elif self.select == ConstTpl.V_OFFSET_PLUS:
                val = fixed_hand.offset_offset + (self.value_real & 0xffff)
                if fixed_hand.space.get_type() != 1:  # If we are not a constant
                    return val
                else:  # If we are a constant, shift by the truncation amount
                    val >>= 8 * (self.value_real >> 16)
                    return val
        elif self.type == ConstTpl.REAL:
            return self.value_real
        return 0

    def fix_space(self, walker):
        if self.type in [ConstTpl.J_CURSPACE, ConstTpl.HANDLE]:
            if self.select == ConstTpl.V_SPACE:
                return walker.get_cur_space()
            else:
                fixed_hand = walker.get_fixed_handle(self.handle_index)
                return fixed_hand.temp_space
        elif self.type == ConstTpl.SPACEID:
            return self.value_spaceid
        elif self.type in [ConstTpl.J_FLOWREF, ConstTpl.J_FLOWDEST]:
            return walker.get_flow_ref_addr().get_address_space()
        raise SleighException("ConstTpl is not a spaceid as expected")

    def fillin_space(self, hand, walker):
        if self.type == ConstTpl.J_CURSPACE:
            hand.space = walker.get_cur_space()
            return
        elif self.type == ConstTpl.HANDLE:
            fixed_hand = walker.get_fixed_handle(self.handle_index)
            if self.select == ConstTpl.V_SPACE:
                hand.space = fixed_hand.space
                return
        else:
            raise SleighException("ConstTpl is not a spaceid as expected")

    def fillin_offset(self, hand, walker):
        if self.type == ConstTpl.HANDLE:
            fixed_hand = walker.get_fixed_handle(self.handle_index)
            hand.offset_space = fixed_hand.offset_space
            hand.offset_offset = fixed_hand.offset_offset
            hand.offset_size = fixed_hand.offset_size
            hand.temp_space = fixed_hand.temp_space
            hand.temp_offset = fixed_hand.temp_offset
        else:
            if self.select == ConstTpl.V_SPACE:
                return walker.get_cur_space().get_pointer_size()
            elif self.select in [ConstTpl.V_OFFSET, ConstTpl.V_SIZE]:
                return self.fix(walker)
            elif self.select == ConstTpl.V_OFFSET_PLUS:
                hand.offset_ offset = self.value_real & 0xffff
                if fixed_hand.space.get_type() != 1:  # If we are not a constant
                    return hand.offset_offset + (self.value_real & 0xffff)
                else:  # If we are a constant, shift by the truncation amount
                    offset >>= 8 * (self.value_real >> 16)
                    return offset

    def restore_xml(self, parser, factory):
        el = parser.start("const_tpl")
        typestr = el.get_attribute("type")
        if typestr == "real":
            self.type = ConstTpl.REAL
            self.value_real = int(el.get_attribute("val"), 16)
        elif typestr == "handle":
            self.type = ConstTpl.HANDLE
            self.handle_index = int(el.get_attribute("val"))
            selstr = el.get_attribute("s")
            if selstr == "space":
                self.select = ConstTpl.V_SPACE
            elif selstr == "offset":
                self.select = ConstTpl.V_OFFSET
            elif selstr == "size":
                self.select = ConstTpl.V_SIZE
            else:
                raise SleighException("Bad handle selector")
        elif typestr in ["start", "next"]:
            self.type = [ConstTpl.J_START, ConstTpl.J_NEXT][["start" == typestr, "next" == typestr]]
        elif typestr in ["curspace", "curspace_size"]:
            self.type = [ConstTpl.J_CURSPACE, ConstTpl.J_CURSPACE_SIZE][["curspace" == typestr, "curspace_size" == typestr]]
        elif typestr in ["flowref", "flowref_size"]:
            self.type = [ConstTpl.J_FLOWREF, ConstTpl.J_FLOWREF_SIZE][["flowref" == typestr, "flowref_size" == typestr]]
        elif typestr in ["flowdest", "flowdest_size"]:
            self.type = [ConstTpl.J_FLOWDEST, ConstTpl.J_FLOWDEST_SIZE][["flowdest" == typestr, "flowdest_size" == typestr]]
        else:
            raise SleighException("Bad xml for ConstTpl")
        parser.end(el)

    def __str__(self):
        if self.type in [ConstTpl.SPACEID, ConstTpl.REAL]:
            return str(self.value_real)
        elif self.type == ConstTpl.HANDLE:
            if self.select == ConstTpl.V_SPACE:
                return "[handle:space]"
            elif self.select == ConstTpl.V_SIZE:
                return "[handle:size]"
            elif self.select == ConstTpl.V_OFFSET:
                return "[handle:offset]"
            else:
                return f"[handle:offset+{self.value_real}]"
        elif self.type in [ConstTpl.J_CURSPACE, ConstTpl.J_CURSPACE_SIZE]:
            return "[curspace]"
        elif self.type in [ConstTpl.J_FLOWDEST, ConstTpl.J_FLOWDEST_SIZE]:
            return "[flowdest]"
        elif self.type == ConstTpl.J_START:
            return "[start]"
        else:
            raise RuntimeError("This should be unreachable")
