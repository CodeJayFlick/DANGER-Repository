Here is the translation of the given Java code into equivalent Python:

```Python
class AssemblyParseMachine:
    def __init__(self, parser, buffer, pos, last_tok, labels):
        self.parser = parser
        self.output = []
        self.stack = [0]
        self.tree_stack = []
        self.buffer = buffer
        self.pos = pos
        self.last_tok = last_tok
        self.id = next_machine_id
        self.labels = labels

    def __hash__(self):
        result = hash(self.pos)
        for s in self.output:
            result *= 31
            result += s
        # Does not distinguish among multiple matches on a single terminal
        for s in self.tree_stack:
            result *= 31
            result += hash(s)
        if self.accepted:
            result *= 31
            result += 1
        else:
            result *= 31
            result -= 1
        return result

    def __eq__(self, other):
        if not isinstance(other, AssemblyParseMachine):
            return False
        apm = AssemblyParseMachine(self.parser, self.buffer, self.pos, self.last_tok, self.labels)
        if apm.pos != self.pos:
            return False
        if not set(apm.output) == set(self.output):
            return False
        if list(apm.stack) != list(self.stack):
            return False
        if list(apm.tree_stack) != list(self.tree_stack):
            return False
        if self.accepted != apm.accepted:
            return False
        if self.error != apm.error:
            return False
        return True

    def __lt__(self, other):
        result = self.pos - other.pos
        if result < 0:
            return True
        elif result > 0:
            return False
        else:
            for s in self.stack:
                if s not in other.stack:
                    return True
            for s in self.tree_stack:
                if s not in other.tree_stack:
                    return True
            if self.accepted and !other.accepted:
                return True
            elif !self.accepted and other.accepted:
                return False
            else:
                result = self.error - other.error
                if result < 0:
                    return True
                elif result > 0:
                    return False
                else:
                    return 0

    def copy(self):
        c = AssemblyParseMachine(self.parser, self.buffer, self.pos, self.last_tok, self.labels)
        c.output.clear()
        c.output.extend(self.output)

        c.stack.clear()
        c.stack.extend(self.stack)

        c.tree_stack.clear()
        c.tree_stack.extend(self.tree_stack)

        c.accepted = self.accepted
        c.error = self.error

        return c

    def do_action(self, a, tok, results, visited):
        if isinstance(a, ShiftAction):
            m = self.copy()
            m.stack.append(a.new_state_num)
            m.tree_stack.append(tok)
            m.last_tok = tok
            m.pos += len(tok.string) + 1
            m.exhaust(results, visited)

        elif isinstance(a, ReduceAction):
            prod = a.prod
            branch = AssemblyParseBranch(self.parser.grammar, prod)
            for sym in prod:
                self.stack.pop()
                branch.append(self.tree_stack.pop())
            for aa in self.parser.actions.get(self.stack[-1], prod.lhs()):
                ga = Action(aa)
                m = self.copy()
                m.stack.append(ga.new_state_num)
                m.tree_stack.append(branch)
                m.exhaust(results, visited)

        elif isinstance(a, AcceptAction):
            results.add(self)

    def consume(self, t, tok, results, visited):
        as_ = self.parser.actions.get(self.stack[-1], t)
        for a in as_:
            if isinstance(a, ShiftAction) or isinstance(a, ReduceAction):
                do_action(a, tok, results, visited)
            elif isinstance(a, AcceptAction):
                return

    def find_loop(self, machine, visited):
        for v in visited:
            if v == self:
                continue
            if v.pos != self.pos:
                continue
            if list(v.stack) != list(self.stack):
                continue
            return v
        return None

    @property
    def tree(self):
        if not self.accepted:
            raise AssertionError("INTERNAL: Machine has not accepted its buffer")
        if self.pos != len(self.buffer):
            raise AssertionError("INTERNAL: Machine has not emptied its buffer")
        if list(self.tree_stack)[-1].sym != AssemblyEOI.EOI:
            raise AssertionError("INTERNAL: Machine has not encountered end of input marker")
        return self.tree_stack.pop()

    def exhaust(self, results=None, visited=None):
        try:
            for t in self.parser.actions.get_expected(self.stack[-1]):
                unmatched = set(t)
                for tok in t.match(self.buffer, self.pos, self.parser.grammar, self.labels):
                    unmatched.remove(t)
                    consume(t, tok, results, visited)

        except AssertionError as e:
            if str(e) == "INTERNAL: Tried to step a machine with errors":
                m = self.copy()
                m.error = 1
                m.got = self.buffer[self.pos:]
                m.expected = set(unmatched)
                results.add(m)
                return

    def __str__(self):
        return f"{list(self.stack)}:{self.tree_stack}:{self.buffer} ({self.pos})"

next_machine_id = 0