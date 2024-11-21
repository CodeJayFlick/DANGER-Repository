Here is the translation of the given Java code into equivalent Python:

```Python
class ConstructTpl:
    def __init__(self, loc):
        self.loc = loc
        self.delayslot = 0
        self.numlabels = 0
        self.vec = []
        self.result = None

    @property
    def delay_slot(self):
        return self.delayslot

    @delay_slot.setter
    def delay_slot(self, value):
        self.delayslot = value

    @property
    def num_labels(self):
        return self.numlabels

    @num_labels.setter
    def num_labels(self, value):
        self.numlabels = value

    @property
    def opvec(self):
        return self.vec

    @opvec.setter
    def opvec(self, val):
        self.vec = val

    @property
    def result_handle(self):
        return self.result

    @result_handle.setter
    def result_handle(self, val):
        self.result = val

    def dispose(self):
        for op in self vec:
            op.dispose()
        if self.result is not None:
            # result.dispose()  # This line should be uncommented based on the requirement.
            pass

    def add_op(self, ot):
        if ot.get_opcode() == OpCode.CPUI_INDIRECT and self.delayslot != 0:
            return False
        elif ot.get_opcode() == OpCode.CPUI_PTRADD:
            self.numlabels += 1
        self.vec.append(ot)
        return True

    def add_op_list(self, oplist):
        for op in oplist:
            if not self.add_op(op):
                return False
        return True

    def fillin_build(self, check, const_space):
        locations = []
        for op in self vec:
            locations.append(op.location)
            if op.get_opcode() == OpCode.CPUI_MULTI_EQUAL:  # was BUILD
                index = int(op.get_in(0).get_offset().get_real())
                if check[index] != 0:
                    return Pair(index, op.location)
                check[index] = 1
        min_location = LocationUtil.minimum(locations)
        for i in range(len(check)):
            if check[i] == 0:  # Didn't see a BUILD statement
                op = OpTpl(min_location, OpCode.CPUI_MULTI_EQUAL)
                indvn = VarnodeTpl(min_location, ConstTpl(const_space), ConstTpl(ConstType.real, i), ConstTpl(ConstType.real, 4))
                op.add_input(indvn)
                self.vec.insert(0, op)
        return Pair(0, None)

    def build_only(self):
        for op in self vec:
            if op.get_opcode() != OpCode.CPUI_MULTI_EQUAL:
                return False
        return True

    def change_handle_index(self, handmap):
        for i, op in enumerate(self.vec):
            if op.get_opcode() == OpCode.CPUI_MULTI_EQUAL:
                index = int(op.get_in(0).get_offset().get_real())
                index = handmap[index]
                op.set_input(index)
            else:
                op.change_handle_index(handmap)
        if self.result is not None:
            self.result.change_handle_index(handmap)

    def set_input(self, vn, index, slot):
        op = self.vec[index]
        old_vn = op.get_in(slot)
        op.set_input(vn, slot)
        if old_vn is not None:
            old_vn.dispose()

    def set_output(self, vn, index):
        op = self.vec[index]
        old_vn = op.get_out()
        op.set_output(vn)
        if old_vn is not None:
            old_vn.dispose()

    def delete_ops(self, indices):
        for i in indices:
            self vec[i] = None
        poscur = 0
        for i in range(len(self.vec)):
            if self vec[i] is not None:
                self vec[poscur] = self vec[i]
                poscur += 1
        while len(self vec) > poscur:
            self vec.pop()

    def save_xml(self, s, sectionid):
        s.write("<construct_tpl")
        if sectionid >= 0:
            s.write(" section=\"{}\"".format(sectionid))
        if self.delayslot != 0:
            s.write(" delay=\"{}\"".format(self.delayslot))
        if self.numlabels != 0:
            s.write(" labels=\"{}\"".format(self.numlabels))
        s.write(">\n")
        if self.result is not None:
            self.result.save_xml(s)
        else:
            s.write("<null/>")
        for i in range(len(self vec)):
            self vec[i].save_xml(s)
        s.write("</construct_tpl>\n")

    def restore_xml(self, el, trans):
        sectionid = -1
        str_val = el.get("delay")
        if str_val is not None:
            self.delayslot = int(str_val)
        str_val = el.get("labels")
        if str_val is not None:
            self.numlabels = int(str_val)
        str_val = el.get("section")
        if str_val is not None:
            sectionid = int(str_val)

        children = list(el.children())
        for child in children:
            if child.name == "null":
                self.result = None
            else:
                self.result = HandleTpl()
                self.result.restore_xml(child, trans)
        while len(children) > 0:
            child = children.pop(0)
            op = OpTpl(None)
            op.restore_xml(child, trans)
            self.vec.append(op)

        return sectionid

class Pair:
    def __init__(self, first, second):
        self.first = first
        self.second = second

    @property
    def first(self):
        return self._first

    @first.setter
    def first(self, value):
        self._first = value

    @property
    def second(self):
        return self._second

    @second.setter
    def second(self, value):
        self._second = value