class CommentLineDispenser:
    def __init__(self, var, width, fill_amount, prefix):
        self.comments = var.get_comment().splitlines()
        self.width = width
        self.fill_amount = fill_amount
        self.index = 0

    def has_more_lines(self):
        return self.index < len(self.comments)

    def get_next_line(self):
        if self.has_more_lines():
            line = self.clip(self.comments[self.index], self.width)
            self.index += 1
            return line
        else:
            return None

    def dispose(self):
        pass


# Example usage:

class Variable:
    def __init__(self, comment):
        self.comment = comment

    def get_comment(self):
        return self.comment


def string_utilities_to_lines(s):
    return s.splitlines()


def clip(line, width):
    if len(line) > width:
        return line[:width].rstrip() + '...'
    else:
        return line
