class CombinedGTreeFilter:
    def __init__(self, filter1: 'CombinedGTreeFilter', filter2: 'CombinedGTreeFilter'):
        self.filter1 = filter1
        self.filter2 = filter2

    def accepts_node(self, node):
        return self.filter1.accepts_node(node) and self.filter2.accepts_node(node)

    def show_filter_matches(self):
        return self.filter1.show_filter_matches() and self.filter2.show_filter_matches()
