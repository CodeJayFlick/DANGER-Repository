class SubtableSymbol:
    def __init__(self, location):
        self.location = location
        self.pattern = None
        self.decision_tree = None
        super().__init__()

    @property
    def beingbuilt(self):
        return self._beingbuilt

    @beingbuilt.setter
    def beingbuilt(self, value):
        self._beingbuilt = value

    @property
    def errors(self):
        return self._errors

    @errors.setter
    def errors(self, value):
        self._errors = value

    def add_constructor(self, constructor):
        if not hasattr(self, 'constructors'):
            self.constructors = []
        self.constructors.append(constructor)
        for i in range(len(self.constructors)):
            self.constructors[i].set_id(i)

    @property
    def pattern_expression(self):
        raise SleighError("Cannot use subtable in expression", None)

    def get_fixed_handle(self, hand, pos):
        raise SleighError("Cannot use subtable in expression", None)

    @property
    def size(self):
        return -1

    def print(self, s, pos):
        raise SleighError("Cannot use subtable in expression", None)

    def collect_local_values(self, results):
        for constructor in self.constructors:
            constructor.collect_local_exports(results)

    @property
    def type(self):
        return 'subtable_symbol'

    def dispose(self):
        if hasattr(self, 'pattern'):
            self.pattern.dispose()
        if hasattr(self, 'decision_tree'):
            self.decision_tree.dispose()
        for i in range(len(self.constructors)):
            self.constructors[i].dispose()

    def save_xml_header(self, s):
        s.write("<subtable_ym_head")
        super().save_sleigh_symbol_xml_header(s)
        s.write("/>\n")

    def restore_xml(self, el, trans):
        num_ct = int(el.get('numct'))
        self.constructors.reserve(num_ct)

        children = list(el.children())
        for child in children:
            if child.tag == 'constructor':
                constructor = Constructor(None)
                add_constructor(constructor)
                constructor.restore_xml(child, trans)
            elif child.tag == 'decision':
                self.decision_tree = DecisionNode()
                self.decision_tree.restore_xml(child, None, self)

    def build_decision_tree(self, props):
        if not hasattr(self, 'pattern'):
            return  # Pattern not fully formed
        self.decision_tree = DecisionNode(None)
        for i in range(len(self.constructors)):
            constructor = self.constructors[i]
            token_pattern = constructor.get_pattern()
            pattern = token_pattern.get_pattern()
            if pattern.num_disjoint() == 0:
                self.decision_tree.add_constructor_pair(pattern, constructor)
            else:
                for j in range(pattern.num_disjoint()):
                    self.decision_tree.add_constructor_pair(pattern.get_disjoint(j), constructor)

        self.decision_tree.split(props)  # Create the decision strategy

    def build_pattern(self):
        if hasattr(self, 'pattern'):
            return self.pattern
        errors = False
        beingbuilt = True
        pattern = TokenPattern(Location.INTERNALLY_DEFINED)
        if not self.constructors:
            print("Error: There are no constructors in table:", self.name())
            errors = True
            return pattern

        try:
            self.constructors[0].build_pattern()
        except SleighError as err:
            print(f"Error: {err.message}: for {self.constructors[0]}")
            errors = True

        pattern = self.constructors[0].get_pattern()
        for i in range(1, len(self.constructors)):
            try:
                constructor = self.constructors[i]
                constructor.build_pattern()
            except SleighError as err:
                print(f"Error: {err.message}: for {constructor}")
                errors = True

        pattern.simplify_pattern()

    def build_xml_header(self):
        s.write("<subtable_ym_head")
        super().save_sleigh_symbol_xml_header(s)
        s.write("/>\n")

class TokenPattern:
    pass
