class HandleTpl:
    def __init__(self):
        self.space = None
        self.size = None
        self.ptrspace = None
        self.ptroffset = None
        self.ptrsize = None
        self.temp_space = None
        self.temp_offset = None

    def get_space(self):
        return self.space

    def get_ptr_space(self):
        return self.ptrspace

    def get_ptroffset(self):
        return self.ptroffset

    def get_ptr_size(self):
        return self.ptrsize

    def get_size(self):
        return self.size

    def get_temp_space(self):
        return self.temp_space

    def get_temp_offset(self):
        return self.temp_offset

    def set_size(self, sz):
        if not isinstance(sz, ConstTpl):
            raise TypeError("sz must be of type ConstTpl")
        self.size = sz

    def set_ptr_size(self, sz):
        if not isinstance(sz, ConstTpl):
            raise TypeError("sz must be of type ConstTpl")
        self.ptrsize = sz

    def set_ptroffset(self, val):
        if not isinstance(val, int) or val < 0:
            raise ValueError("val must be a non-negative integer")
        self.ptroffset = ConstTpl(ConstTpl.const_type.real, val)

    def set_temp_offset(self, val):
        if not isinstance(val, int) or val < 0:
            raise ValueError("val must be a non-negative integer")
        self.temp_offset = ConstTpl(ConstTpl.const_type.real, val)

    def fix(self, hand, walker):
        if self.ptrspace.get_type() == ConstTpl.const_type.real:
            space.fillin_space(hand, walker)
            hand.size = int(size.fix(walker))
            ptroffset.fillin_offset(hand, walker)
        else:
            hand.space = space.fix_space(walker)
            hand.size = int(size.fix(walker))
            hand.offset_offset = ptroffset.fix(walker)
            hand.offset_space = ptrspace.fix_space(walker)

    def change_handle_index(self, handmap):
        self.space.change_handle_index(handmap)
        self.size.change_handle_index(handmap)
        self.ptrspace.change_handle_index(handmap)
        self.ptroffset.change_handle_index(handmap)
        self.ptrsize.change_handle_index(handmap)
        self.temp_space.change_handle_index(handmap)
        self.temp_offset.change_handle_index(handmap)

    def save_xml(self, s):
        s.write("<handle_tpl>")
        space.save_xml(s)
        size.save_xml(s)
        ptrspace.save_xml(s)
        ptroffset.save_xml(s)
        ptrsize.save_xml(s)
        temp_space.save_xml(s)
        temp_offset.save_xml(s)
        s.write("</handle_tpl>\n")

    def restore_xml(self, el, trans):
        list = el.get_children()
        space.restore_xml(list[0], trans)
        size.restore_xml(list[1], trans)
        ptrspace.restore_xml(list[2], trans)
        ptroffset.restore_xml(list[3], trans)
        ptrsize.restore_xml(list[4], trans)
        temp_space.restore_xml(list[5], trans)
        temp_offset.restore_xml(list[6], trans)

    def dispose(self):
        pass  # TODO Auto-generated method stub

class ConstTpl:
    const_type = None
    real = "real"
    int = "int"

    def __init__(self, val=None):
        self.val = val

    @property
    def get_type(self):
        return self.const_type

    def fix(self, walker):
        pass  # TODO Auto-generated method stub

class FixedHandle:
    space = None
    size = None
    offset_offset = None
    temp_space = None
    temp_offset = None

    @property
    def get_scale(self):
        return self.space.get_scale()

    @property
    def get_mask(self):
        return self.space.get_mask()
