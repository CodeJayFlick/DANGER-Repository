Here is the translation of the Java code into Python:

```Python
class OperandSymbol:
    CODE_ADDRESS = 1
    OFFSET_IRREL = 2
    VARIABLE_LEN = 4
    MARKED = 8

    def __init__(self, location):
        self.reloffset = None
        self.offsetbase = -1
        self.minimumlength = None
        self.hand = None
        self.localexp = None
        self.triple = None
        self.defexp = None
        self.flags = 0

    def get_relative_offset(self):
        return self.reloffset

    def get_offset_base(self):
        return self.offsetbase

    def get_minimum_length(self):
        return self.minimumlength

    def get_defining_expression(self):
        return self.defexp

    def get_defining_symbol(self):
        return self.triple

    def get_index(self):
        return self.hand

    def set_code_address(self):
        self.flags |= OperandSymbol.CODE_ADDRESS

    def is_code_address(self):
        return (self.flags & OperandSymbol.CODE_ADDRESS) != 0

    def set_offset_irrelevant(self):
        self.flags |= OperandSymbol.OFFSET_IRREL

    def is_offset_irrelevant(self):
        return (self.flags & OperandSymbol.OFFSET_IRREL) != 0

    def set_variable_length(self):
        self.flags |= OperandSymbol.VARIABLE_LEN

    def is_variable_length(self):
        return (self.flags & OperandSymbol.VARIABLE_LEN) != 0

    def set_mark(self):
        self.flags |= OperandSymbol.MARKED

    def clear_mark(self):
        self.flags &= ~OperandSymbol.MARKED

    def is_marked(self):
        return (self.flags & OperandSymbol.MARKED) != 0

    @property
    def pattern_expression(self):
        return self.localexp

    @property
    def symbol_type(self):
        return 'operand_symbol'

    def define_operand(self, pe):
        if self.defexp or self.triple:
            raise SleighError("Redefining operand from " + str(pe.location), self.get_location())
        self.defexp = pe
        self.localexp.lay_claim()

    def define_operand(self, tri):
        if self.defexp or self.triple:
            raise SleighError("Redefining operand " + str(tri.name) + " from " + str(tri.location), self.get_location())
        self.triple = tri

    def dispose(self):
        PatternExpression.release(self.localexp)
        if self.defexp:
            PatternExpression.release(self.defexp)

    @property
    def varnode(self):
        if self.defexp:
            return VarnodeTpl(self.get_location(), self.hand, True)  # Definite constant handle
        elif self.triple and isinstance(self.triple, SpecificSymbol):
            return (self.triple).get_varnode()
        else:
            return VarnodeTpl(self.get_location(), self.hand, False)  # Possible dynamic handle

    def get_fixed_handle(self, hnd, pos):
        hnd = pos.get_fixed_handle(self.hand)

    @property
    def size(self):
        if self.triple:
            return self.triple.size()
        else:
            return 0

    def print(self, s, pos):
        pos.push_operand(self.hand)
        if self.triple:
            if isinstance(self.triple, SubtableSymbol):
                pos.get_constructor().print(s, pos)
            else:
                self.triple.print(s, pos)
        elif self.defexp:
            val = self.defexp.value(pos)
            if val >= 0:
                s.append("0x")
                s.append(Long.toHexString(val))
            else:
                s.append("-0x")
                s.append(Long.toHexString(-val))
        pos.pop_operand()

    def collect_local_values(self, results):
        if self.triple:
            self.triple.collect_local_values(results)

    @property
    def xml_header(self):
        return "<operand_sym " + self.save_sleigh_symbol_xml_header() + "/>"

    def save_xml(self, s):
        s.append("<operand_sym")
        self.save_sleigh_symbol_xml_header(s)
        if self.triple:
            s.append(" subsym=\"0x" + Long.toHexString(self.triple.id) + "\"")
        else:
            s.append(" off=\"" + str(self.reloffset) + "\" base=\"" + str(self.offsetbase) + "\" minlen=\"" + str(self.minimumlength) + "\"")
        if self.is_code_address():
            s.append(" code=\"true\"")
        s.append(" index=\"" + str(self.hand) + "\">")
        self.localexp.save_xml(s)
        if self.defexp:
            self.defexp.save_xml(s)
        s.append("</operand_sym>\n")

    def save_xml_header(self, s):
        s.append("<operand_sym_head" + self.save_sleigh_symbol_xml_header() + "/>\n")

    @property
    def get_location(self):
        return None

    def restore_xml(self, el, trans):
        self.defexp = None
        self.triple = None
        self.flags = 0
        self.hand = XmlUtils.decode_unknown_int(el.get_attribute_value("index"))
        self.reloffset = XmlUtils.decode_unknown_int(el.get_attribute_value("off"))
        self.offsetbase = XmlUtils.decode_unknown_int(el.get_attribute_value("base"))
        self.minimumlength = XmlUtils.decode_unknown_int(el.get_attribute_value("minlen"))
        value = el.get_attribute_value("subsym")
        if value:
            id = XmlUtils.decode_unknown_int(value)
            self.triple = trans.find_symbol(id)
        if XmlUtils.decode_boolean(el.get_attribute_value("code")):
            self.flags |= OperandSymbol.CODE_ADDRESS
        children = el.get_children()
        first_child = children[0]
        self.localexp = PatternExpression.restore_expression(first_child, trans)
        self.localexp.lay_claim()
        if len(children) > 1:
            second_child = children[1]
            self.defexp = PatternExpression.restore_expression(second_child, trans)
            self.defexp.lay_claim()

class SleighError(Exception):
    pass

class VarnodeTpl:
    def __init__(self, location, hand, definite_constant_handle):
        self.location = location
        self.hand = hand
        self.definite_constant_handle = definite_constant_handle

    @property
    def get_location(self):
        return self.location

    @property
    def get_hand(self):
        return self.hand

class PatternExpression:
    @staticmethod
    def release(pe):
        pass

    @staticmethod
    def restore_expression(el, trans):
        pass

    @property
    def value(self, pos):
        pass

    @property
    def lay_claim(self):
        pass

class XmlUtils:
    @staticmethod
    def decode_unknown_int(value):
        return None

    @staticmethod
    def decode_boolean(value):
        return False

    @staticmethod
    def get_attribute_value(el, name):
        return el.get(name)

    @staticmethod
    def get_children(el):
        return []

class SleighBase:
    pass

class TripleSymbol:
    @property
    def id(self):
        return None

    @property
    def location(self):
        return None

    @property
    def name(self):
        return None

    @property
    def type(self):
        return 'valuemap_symbol'

    def get_varnode(self):
        pass

class SpecificSymbol:
    pass

class SubtableSymbol(SpecificSymbol):
    pass