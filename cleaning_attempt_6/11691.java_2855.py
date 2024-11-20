class EquationCat:
    def __init__(self, location, l, r):
        self.location = location
        self.left = l
        self.right = r

    def dispose(self):
        del self.left
        del self.right

    def gen_pattern(self, ops):
        self.left.gen_pattern(ops)
        self.right.gen_pattern(ops)
        token_pattern = self.left.get_token_pattern().concatenate(self.right.get_token_pattern())
        # Assuming get_token_pattern() and concatenate() methods exist in the TokenPattern class
        return token_pattern

    def operand_order(self, ct, order):
        self.left.operand_order(ct, order)  # List operands left to right
        self.right.operand_order(ct, order)

    def resolve_operand_left(self, state):
        res = self.left.resolve_operand_left(state)
        if not res:
            return False

        cur_base = state.base
        cur_offset = state.offset
        if (not self.left.get_token_pattern().get_left_ellipsis()) and (not self.left.get_token_pattern().get_right_ellipsis()):
            # Keep the same base, but add to its size
            state.offset += self.left.get_token_pattern().get_minimum_length()
        elif state.cur_rightmost != -1:
            state.base = state.cur_rightmost
            state.offset = state.size
        elif state.size != -1:
            state.offset += state.size
        else:
            # We have no anchor, so set base to -2
            state.base = -2

        cur_rightmost = state.cur_rightmost
        cur_size = state.size
        res = self.right.resolve_operand_left(state)
        if not res:
            return False

        state.base = cur_base  # Restore base and offset
        state.offset = cur_offset
        if state.cur_rightmost == -1:
            if (state.size != -1) and (cur_rightmost != -1) and (cur_size != -1):
                state.cur_rightmost = cur_rightmost
                state.size += cur_size

        return True


# Example usage:

location = "Location"
l = PatternEquation(location, 10)
r = PatternEquation(location, 20)

ec = EquationCat(location, l, r)

ops = []
token_pattern = ec.gen_pattern(ops)  # Generate pattern
print(token_pattern)

ct = Constructor()
order = []

ec.operand_order(ct, order)  # Order operands

state = OperandResolve()

res = ec.resolve_operand_left(state)
if res:
    print("Operand resolved successfully")
else:
    print("Failed to resolve operand")

