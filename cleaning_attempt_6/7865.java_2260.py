class MDThrowAttribute:
    def __init__(self):
        self.args_list = None
        self.has_throw = True

    def parse(self, dmang):
        if dmang.peek() == 'Z':
            dmang.increment()
            self.has_throw = False
        else:
            self.args_list.parse(dmang)

    def insert(self, builder):
        if self.has_throw:
            builder.append("throw (")
            self.args_list.insert(builder)
            builder.append(")")
