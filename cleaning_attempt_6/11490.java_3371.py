class OperandValue:
    def __init__(self):
        pass

    def __init__(self, i, c):
        self.index = i
        self.ct = c

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, value):
        self._index = value

    @property
    def ct(self):
        return self._ct

    @ct.setter
    def ct(self, value):
        self._ct = value

    def __hash__(self):
        result = 0
        result += self.index
        result *= 31
        result += hash(self.ct)
        return result

    def __eq__(self, other):
        if not isinstance(other, OperandValue):
            return False
        if self.index != other.index:
            return False
        if self.ct != other.ct:
            return False
        return True

    def min_value(self):
        raise SleighException("Operand used in pattern expression")

    def max_value(self):
        raise SleighException("Operand used in pattern expression")

    def get_value(self, walker):
        sym = self.ct.get_operand(self.index)
        patexp = sym.get_defining_expression()
        if patexp is None:
            def_sym = sym.get_defining_symbol()
            if def_sym is not None:
                patexp = def_sym.get_pattern_expression()
        else:
            return 0
        tempstate = ConstructState(None)
        newwalker = ParserWalker(walker.parser_context())
        newwalker.set_out_of_band_state(self.ct, self.index, tempstate, walker)
        res = patexp.get_value(newwalker)
        return res

    def restore_xml(self, parser, lang):
        el = parser.start("operand_exp")
        self.index = SpecXmlUtils.decode_int(el.attribute("index"))
        tabid = SpecXmlUtils.decode_int(el.attribute("table"))
        ctid = SpecXmlUtils.decode_int(el.attribute("ct"))
        sym = lang.symbol_table().find_symbol(tabid)
        self.ct = sym.get_constructor(ctid)
        parser.end(el)

    def __str__(self):
        sb = StringBuilder()
        sb.append("[opval:" + self.ct.get_operand(self.index).name())
        patexp = self.ct.get_operand(self.index).get_defining_expression()
        if patexp is not None:
            sb.append(" exp ")
        else:
            def_sym = self.ct.get_operand(self.index).get_defining_symbol()
            if def_sym is not None:
                sb.append(" sym ")
                patexp = def_sym.get_pattern_expression()
            else:
                sb.append("]")
                return sb.toString()
        sb.append(patexp)
        sb.append("]")
        return sb.toString()

class SleighException(Exception):
    pass

class ConstructState:
    def __init__(self, value):
        self.value = value
