class PcodeBuilder:
    def __init__(self, lbcnt):
        self.label_base = labelcount = lbcnt
        self.walker = None

    def dispose(self):
        pass

    @property
    def label_base(self):
        return self._label_base

    @label_base.setter
    def label_base(self, value):
        self._label_base = value

    @property
    def walker(self):
        return self._walker

    @walker.setter
    def walker(self, value):
        self._walker = value

    def dump(self, op):
        pass  # abstract method in Python

    def append_build(self, bld, secnum):
        raise NotImplementedError("appendBuild is not implemented")

    def append_cross_build(self, bld, secnum):
        raise NotImplementedError("appendCrossBuild is not implemented")

    def delay_slot(self, op):
        raise NotImplementedError("delaySlot is not implemented")

    def set_label(self, op):
        raise NotImplementedError("setLabel is not implemented")

    def build(self, construct, secnum):
        if construct is None:
            raise ValueError("Pcode is not implemented for this constructor")
        
        old_base = self.label_base
        self.label_base = self.label_count
        self.label_count += construct.num_labels()

        ops = list(construct.get_opvec())
        for op in ops:
            if op.get_opcode() == CPUI_MULTIEQUAL:  # formerly BUILD
                self.append_build(op, secnum)
            elif op.get_opcode() == CPUI_INDIRECT:  # formerly DELAY_SLOT
                self.delay_slot(op)
            elif op.get_opcode() == CPUI_PTRADD:  # formerly LABELBUILD
                self.set_label(op)
            elif op.get_opcode() == CPUI_PTRSUB:  # formerly CROSSBUILD
                self.append_cross_build(op, secnum)
            else:
                self.dump(op)

        self.label_base = old_base

class ConstructTpl:
    def __init__(self):
        pass

    @property
    def num_labels(self):
        raise NotImplementedError("numLabels is not implemented")

    @property
    def get_opvec(self):
        raise NotImplementedError("getOpvec is not implemented")
