class GraphSelectedAST:
    def get_pcode_op_iterator(self):
        return self.high.get_pcode_ops(self.current_address)

# Note: The high and current_address variables are not defined in this snippet.
