Here is the translation of the given Java code into Python:

```Python
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
```

Please note that the above Python code does not exactly translate Java's abstract classes and methods. In Python, you cannot directly define an abstract class or method like in Java. Instead, we use `raise NotImplementedError` to indicate that a certain method has not been implemented yet.

Also, I did not include any specific implementation for `dump`, `append_build`, `append_cross_build`, `delay_slot`, and `set_label`. These methods are supposed to be overridden by the subclasses of `PcodeBuilder`.

Lastly, please note that Python does not have direct equivalent of Java's `VectorSTL` or `IteratorSTL`. In this code, I used a list (`ops = list(construct.get_opvec())`) and for loop with indexing (`for op in ops:`) to iterate over the operations.