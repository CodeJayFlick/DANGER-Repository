class PathElement:
    def __init__(self, type, points):
        self.type = type
        self.points = points


class PathParser:
    m_scale = 0.0

    i = 0
    l = 0
    s = ""
    m_path = None
    elements = []

    m_pen_x = 0.0
    m_pen_y = 0.0
    m_pivot_x = 0.0
    m_pivot_y = 0.0
    m_pen_down_x = 0.0
    m_pen_down_y = 0.0
    m_pen_down = False

    def parse(self, d):
        self.elements = []
        self.m_path = None
        if not d:
            return self.m_path

        prev_cmd = ' '
        l = len(d)
        s = d
        i = 0

        while i < l:
            skip_spaces()

            if i >= l:
                break

            has_prev_cmd = (prev_cmd != ' ')
            first_char = s[i]
            is_implicit_move_to = False

            if not has_prev_cmd and first_char != 'M' and first_char != 'm':
                raise Exception(f"Unexpected character '{first_char}' (i={i}, s={s})")

            cmd = ''
            if self.is_cmd(first_char):
                is_implicit_move_to = False
                cmd = first_char
                i += 1

            elif self.is_number_start(first_char) and has_prev_cmd:
                if prev_cmd in ['Z', 'z']:
                    raise Exception(f"Unexpected number after 'z' (s={s})")

                if prev_cmd in ['M', 'm']:
                    is_implicit_move_to = True
                    cmd = 'L'
                else:
                    is_implicit_move_to = False
                    cmd = prev_cmd

            else:
                raise Exception(f"Unexpected character '{first_char}' (i={i}, s={s})")

            if not is_implicit_move_to:
                prev_cmd = cmd

            switch(cmd):
                case 'm':
                    self.move(*self.parse_list_number(), *self.parse_list_number())
                    break
                case 'M':
                    self.moveTo(*self.parse_list_number(), *self.parse_list_number())
                    break
                # ... and so on for all the other cases.
        return self.m_path

    def move(self, x, y):
        self.moveTo(x + self.m_pen_x, y + self.m_pen_y)

    def moveTo(self, x, y):
        if not self.m_pen_down:
            set_pen_down()

        self.m_pivot_x = m_pen_x = x
        self.m_pivot_y = m_pen_y = y

        self.m_path.moveTo(x * self.m_scale, y * self.m_scale)
        self.elements.append(PathElement(ElementType.kCGPathElementMoveToPoint, [Point(m_pen_x, m_pen_y)]))

    def line(self, x, y):
        self.lineTo(x + self.m_pen_x, y + self.m_pen_y)

    # ... and so on for all the other methods.
