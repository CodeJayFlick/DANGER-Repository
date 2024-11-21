Here is the translation of the given Java code into Python:

```Python
class CombinePattern:
    def __init__(self):
        self.context = None
        self.instr = None

    def get_block(self, cont=False):
        return self.context.get_block() if cont else self.instr.get_block()

    def shift_instruction(self, sa):
        self.instr.shift_instruction(sa)

    def always_instruction_true(self):
        return self.instr.always_instruction_true()

    def dispose(self):
        if self.context:
            self.context.dispose()
        if self.instr:
            self.instr.dispose()

    def is_match(self, pos):
        if not self.instr.is_match(pos):
            return False
        if not self.context.is_match(pos):
            return False
        return True

    def always_true(self):
        return self.context.always_true() and self.instr.always_true()

    def always_false(self):
        return self.context.always_false() or self.instr.always_false()

    def do_and(self, b, sa=0):
        if isinstance(b, CombinePattern):
            c = self.context.do_and(b.context, 0)
            i = self.instr.do_and(b.instr, sa)
            return CombinePattern(c, i)
        elif isinstance(b, InstructionPattern):
            i = self.instr.do_and(b, sa)
            return CombinePattern(self.context.simplify_clone(), i)
        else:  # Must be a ContextPattern
            c = self.context.do_and(b, 0)
            newpat = self.instr.simplify_clone()
            if sa < 0:
                newpat.shift_instruction(-sa)
            return CombinePattern(c, newpat)

    def common_sub_pattern(self, b, sa=0):
        if isinstance(b, CombinePattern):
            c = self.context.common_sub_pattern(b.context, 0)
            i = self.instr.common_sub_pattern(b.instr, sa)
            return CombinePattern(c, i)
        elif isinstance(b, InstructionPattern):
            return self.instr.common_sub_pattern(b, sa)
        else:  # Must be a ContextPattern
            return self.context.common_sub_pattern(b, 0)

    def do_or(self, b, sa=0):
        if isinstance(b, CombinePattern):
            res1 = simplify_clone()
            res2 = b.simplify_clone()
            if sa < 0:
                res1.shift_instruction(-sa)
            else:
                res2.shift_instruction(sa)
            return OrPattern(res1, res2)

    def simplify_clone(self):
        if self.context.always_true():
            return self.instr.simplify_clone()
        elif self.instr.always_true():
            return self.context.simplify_clone()
        elif self.context.always_false() or self.instr.always_false():
            return InstructionPattern(False)
        else:
            return CombinePattern(self.context.simplify_clone(), self.instr.simplify_clone())

    def save_xml(self, s):
        s.write("<combine_pat>\n")
        self.context.save_xml(s)
        self.instr.save_xml(s)
        s.write("</combine_pat>\n")

    def restore_xml(self, el):
        children = list(el.getChildren())
        child = children[0]
        self.context = ContextPattern()
        self.context.restore_xml(child)
        child = children[1]
        self.instr = InstructionPattern()
        self.instr.restore_xml(child)

class OrPattern:
    pass

class InstructionPattern:
    def __init__(self, always_true=False):
        self.always_true = always_true
```

Note: This Python code does not include the `ContextPattern`, `InstructionPattern` classes and their methods as they are quite complex. You would need to implement these yourself based on your specific requirements.