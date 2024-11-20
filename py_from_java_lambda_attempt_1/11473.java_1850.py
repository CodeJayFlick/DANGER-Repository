Here is the translation of the Java code into Python:

```Python
class Constructor:
    def __init__(self):
        self.parent = None
        self.operands = []
        self.separators = []
        self.printpiece = []
        self.context = []
        self.templ = None
        self.namedtempl = None
        self.minimumlength = 0
        self.id = 0
        self.firstwhitespace = -1
        self.lineno = -1
        self.flowthruindex = -1

    def __str__(self):
        return f"line {self.lineno} (id {self.parent.getId()}.{self.id})"

    @property
    def print_pieces(self):
        return [piece for piece in self.printpiece]

    @property
    def flow_thru_index(self):
        return self.flowthruindex

    @property
    def minimum_length(self):
        return self.minimumlength

    @id.setter
    def id(self, val):
        self.id = val

    @property
    def parent(self):
        return self.parent

    @property
    def lineno(self):
        return self.lineno

    def get_print_pieces(self):
        return [piece for piece in self.printpiece]

    def get_flow_thru_index(self):
        return self.flowthruindex

    def print(self, walker):
        result = ""
        for piece in self.printpiece:
            if piece and piece[0] == '\n':
                index = ord(piece[1]) - 65
                result += self.operands[index].print(walker)
            else:
                result += piece
        return result

    def print_separator(self, separator_index):
        if separator_index < 0 or separator_index >= len(self.operands):
            return None
        cached_separator = self.separators[separator_index]
        if cached_separator and len(cached_separator) > 0:
            return cached_separator
        cur_pos = 0
        while cur_pos < len(self.printpiece) and (self.printpiece[cur_pos].length() == 0 or self.printpiece[cur_pos][0] != ' '):
            cur_pos += 1
        op_index = 0
        buf = ""
        for i in range(cur_pos, len(self.printpiece)):
            if self.printpiece[i].length() > 0:
                if self.printpiece[i][0] == '\n':
                    if op_index == separator_index:
                        break
                    op_index += 1
                elif op_index == separator_index:
                    buf += self.printpiece[i]
        separator = buf.strip()
        separators[separator_index] = separator
        return separator

    def print_list(self, walker, list):
        for piece in self.printpiece:
            if piece and piece[0] == '\n':
                index = ord(piece[1]) - 65
                self.operands[index].print_list(walker, list)
            elif len(piece) > 0:
                list.append(piece)

    def print_mnemonic(self, walker):
        result = ""
        if self.flowthruindex != -1:
            sym = self.operands[self.flowthruindex].get_defining_symbol()
            if isinstance(sym, SubtableSymbol):
                walker.push_operand(self.flowthruindex)
                result += walker.get_constructor().print_mnemonic(walker)
                walker.pop_operand()
        endind = (self.firstwhitespace == -1) and len(self.printpiece) or self.firstwhitespace
        for i in range(len(self.printpiece)):
            if self.printpiece[i].length() > 0:
                if self.printpiece[i][0] == '\n':
                    index = ord(self.printpiece[i][1]) - 65
                    result += self.operands[index].print(walker)
                else:
                    result += self.printpiece[i]
        return result

    def print_body(self, walker):
        result = ""
        if self.flowthruindex != -1:
            sym = self.operands[self.flowthruindex].get_defining_symbol()
            if isinstance(sym, SubtableSymbol):
                walker.push_operand(self.flowthruindex)
                result += walker.get_constructor().print_body(walker)
                walker.pop_operand()
        if self.firstwhitespace == -1:
            return ""
        for i in range(self.firstwhitespace + 1, len(self.printpiece)):
            if self.printpiece[i].length() > 0:
                if self.printpiece[i][0] == '\n':
                    index = ord(self.printpiece[i][1]) - 65
                    result += self.operands[index].print(walker)
                else:
                    result += self.printpiece[i]
        return result

    def apply_context(self, walker):
        for context_change in self.context:
            context_change.apply(walker)

    @property
    def namedtempl(self):
        return self.namedtempl

    def get_named_templ(self, secnum):
        if not self.namedtempl or len(self.namedtempl) <= secnum:
            return None
        return self.namedtempl[secnum]

    def restore_xml(self, parser, sleigh):
        el = parser.start("constructor")
        symtab = sleigh.get_symbol_table()

        my_id = int(el.getAttribute("parent"))
        self.parent = SubtableSymbol(my_id)
        firstwhitespace = int(el.getAttribute("first"))
        minimumlength = int(el.getAttribute("length"))
        source_and_line = el.getAttribute("line")
        parts = source_and_line.split(":")
        if len(parts) != 2:
            Msg.error(self, "Bad line attribute in .sla file")
            self.lineno = -1
            self.source_file = "UNKNOWN"
        else:
            self.lineno = int(parts[1].strip())
            self.source_file = sleigh.get_source_file_indexer().get_filename(int(parts[0].strip()))

        oplist = []
        piecelist = []
        coplist = []

        subel = parser.peek()
        while not subel.getName().equals("constructor"):
            if subel.getName().equals("oper"):
                my_id = int(subel.getAttribute("id"))
                oplist.append(SubtableSymbol(my_id))
                parser.discardSubTree()
            elif subel.getName().equals("print"):
                piecelist.append(subel.getAttribute("piece"))
                parser.discardSubTree()
            elif subel.getName().equals("opprint"):
                my_id = int(subel.getAttribute("id"))
                operstring = "\n"
                ind = chr(ord('A') + my_id)
                operstring += ind
                piecelist.append(operstring)
                parser.discardSubTree()
            elif subel.getName().equals("context_op"):
                c_op = ContextOp()
                c_op.restore_xml(parser, sleigh)
                coplist.append(c_op)
            elif subel.getName().equals("commit"):
                c_op = ContextCommit()
                c_op.restore_xml(parser, sleigh)
                coplist.append(c_op)

        self.operands = oplist
        self.separators = [""] * (len(self.operands) + 1)
        piecelist.toArray(self.printpiece)
        context = [ContextChange() for _ in range(len(coplist))]
        coplist.toArray(context)
        if len(self.printpiece) == 1 and len(self.printpiece[0]) >= 2 and self.printpiece[0][0] == '\n':
            self.flowthruindex = ord(self.printpiece[0][1]) - 65
        else:
            self.flowthruindex = -1

    def get_ops_print_order(self):
        if self.firstwhitespace == -1:
            return []
        count = 0
        for i in range(self.firstwhitespace + 1, len(self.printpiece)):
            if self.printpiece[i].length() > 0 and self.printpiece[i][0] == '\n':
                count += 1
        res = [i - self.firstwhitespace for _ in range(count)]
        return res

    def __eq__(self, other):
        if not isinstance(other, Constructor):
            return False
        if self.id != other.id:
            return False
        if self.parent.getId() != other.parent.getId():
            return False
        return True

    def __hash__(self):
        return hash((self.parent.getId(), self.id))

class ContextChange:
    pass

class SubtableSymbol:
    pass

class OperandSymbol:
    pass

class FixedHandle:
    pass

class ConstructTpl:
    pass

class HandleTpl:
    pass
```

Note: This is a direct translation of the Java code into Python. It may not be perfect, as some parts might need adjustments based on specific requirements or constraints in your project.