class DecisionNode:
    def __init__(self):
        self.list = []
        self.children = []

    def add_constructor_pair(self, pat, ct):
        clone_pat = DisjointPattern(simplify_clone(pat))
        self.list.append((clone_pat, ct))

    @staticmethod
    def simplify_clone(pattern):
        return pattern

    def get_maximum_length(self, context=False):
        max_len = 0
        for i in range(len(self.list)):
            val = self.list[i][0].get_length(context)
            if val > max_len:
                max_len = val
        return max_len

    @staticmethod
    def get_num_fixed(low, size, context=True):
        count = 0
        mask = (1 << size) - 1
        for i in range(len(self.list)):
            pat_mask = self.list[i][0].get_mask(low, size, context)
            if (pat_mask & mask) == mask:
                count += 1
        return count

    @staticmethod
    def get_score(low, size, context=True):
        num_bins = 2 ** size
        total = 0
        for i in range(len(self.list)):
            pat_mask = self.list[i][0].get_mask(low, size, context)
            if (pat_mask & ((1 << size) - 1)) != ((1 << size) - 1):
                continue
            val = self.list[i][0].get_value(low, size, context)
            total += 1
        if total <= 0:
            return -1.0
        sc = 0.0
        for i in range(num_bins):
            count = [0] * num_bins
            for j in range(len(self.list)):
                pat_mask = self.list[j][0].get_mask(low, size, context)
                if (pat_mask & ((1 << size) - 1)) != ((1 << size) - 1):
                    continue
                val = self.list[j][0].get_value(low, size, context)
                count[val] += 1
            for j in range(num_bins):
                if count[j] <= 0:
                    continue
                p = (count[j] / total)
                sc -= p * math.log(p)
        return sc / math.log(2.0)

    def choose_optimal_field(self):
        score = 0.0
        for sbit in range(get_maximum_length()):
            num_fixed = get_num_fixed(sbit, 1)
            if num_fixed < self.num:
                continue
            sc = get_score(sbit, 1)
            if sc > score:
                score = sc
                start_bit = sbit
                bit_size = 1

    def consistent_values(self, bins, pat):
        m = (2 ** bit_size) - 1
        common_mask = int((m & pat.get_mask(start_bit, bit_size)))
        for i in range(2 ** (32 - bit_size)):
            if ((i & dont_care_mask) != i):
                continue
            bins.append(common_value | i)

    def split(self, props):
        if len(self.list) <= 1:
            self.bit_size = 0
            return

        choose_optimal_field()

        for i in range(len(self.list)):
            pat = self.list[i][0]
            vals = []
            consistent_values(vals, pat)
            for j in range(len(vals)):
                child = DecisionNode(self)
                child.add_constructor_pair(pat, self.list[i][1])
                self.children.append(child)

    def order_patterns(self):
        new_list = list.copy()
        conflict_list = []

        # Check for identical patterns
        for i in range(len(list)):
            for j in range(i + 1):
                if list[i][0].identical(list[j][0]):
                    props.identical_pattern(list[i][1], list[j][1])

    def resolve(self, pos):
        if self.bit_size == 0:
            return [pair[1] for pair in self.list]

        val = int(pos.get_instruction_bits(start_bit, bit_size))
        child = self.children[val]
        return child.resolve(pos)

    @staticmethod
    def save_xml(s):
        s.write("<decision number=\"{}\" context=\"{}\">".format(self.num, "true" if self.context_decision else "false"))
        for i in range(len(list)):
            pair_id = list[i][1].get_id()
            s.write("<pair id=\"{}\">\n".format(pair_id))
            list[i][0].save_xml(s)
            s.write("</pair>\n")
        for child in children:
            child.save_xml(s)
        s.write("</decision>\n")

    @staticmethod
    def restore_xml(el, par):
        self.parent = par
        self.num = int(XmlUtils.decode_unknown_int(el.get_attribute_value("number")))
        self.context_decision = XmlUtils.decode_boolean(el.get_attribute_value("context"))
        self.start_bit = int(XmlUtils.decode_unknown_int(el.get_attribute_value("start")))
        self.bit_size = int(XmlUtils.decode_unknown_int(el.get_attribute_value("size")))

    def __init__(self, par):
        super().__init__()
        self.parent = par
