class LoopValue:
    def __init__(self):
        pass

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def loop(self):
        return self._loop

    @loop.setter
    def loop(self, value):
        self._loop = value

    _is_variable_loop = False
    _is_index = False

    def init(self, vars, matched_pattern, is_delayed, parser):
        self.name = parser.expr
        s = str(parser.regexes[0].group())
        i = -1
        m = re.compile(r"^(.+)-(\\d+)$").match(s)
        if m:
            s = str(m.group(1))
            i = int(str(m.group(2)))
        c = Classes.get_class_from_user_input(s)
        j = 1
        loop = None

        for l in parser.current_sections(SecLoop):
            if (c is not None and isinstance(l, SecLoop) and c.is_assignable_type_of(l.looped_expression.return_type)) or s == "value" or l.looped_expression.is_loop_of(s):
                if j < i:
                    j += 1
                    continue
                elif loop is not None:
                    Skript.error("There are multiple loops that match 'loop-" + s + "'. Use loop-" + s + "-1/2/3/etc. to specify which loop's value you want.", ErrorQuality.SEMANTIC_ERROR)
                    return False
                else:
                    loop = l
                    if j == i:
                        break

        if loop is None:
            Skript.error("There's no loop that matches 'loop-" + s + "'", ErrorQuality.SEMANTIC_ERROR)
            return False

        if isinstance(loop.looped_expression, Variable):
            self._is_variable_loop = True
            if ((Variable) loop.looped_expression).is_index_loop(s):
                self._is_index = True

        self.loop = loop
        return True

    def is_single(self):
        return True

    @staticmethod
    def get_converted_expr(to):
        if self.is_variable_loop and not self._is_index:
            super_type = Utils.get_super_type(to)
            return ConvertedExpression(self, super_type,
                                        ConverterInfo(Object.class, super_type, lambda o: Converters.convert(o, to), 0))
        else:
            return super.get_converted_expr(to)

    def get_return_type(self):
        if self._is_index:
            return str
        return self.loop.looped_expression.return_type

    @staticmethod
    def get(event):
        if self.is_variable_loop:
            current = loop.current(event)
            if current is None:
                return None
            if self._is_index:
                return [current.key]
            else:
                one = [loop.current(event)]
                return one
        else:
            one = [loop.current(event)]
            return one

    def to_string(self, event, debug):
        if event is None:
            return self.name
        if self.is_variable_loop:
            current = loop.current(event)
            if current is None:
                return Classes.get_debug_message(None)
            elif self._is_index:
                return f"\"{current.key}\""
            else:
                return str(current.value)
        else:
            return str(loop.current(event))
