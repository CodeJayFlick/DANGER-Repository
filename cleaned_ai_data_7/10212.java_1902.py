class LSHCosineVector:
    def __init__(self):
        self.hash = []
        self.length = 0.0
        self.hashcount = 0

    def install_features(self, feature, wfactory, idflookup):
        if len(feature) == 0:
            return
        lasthash = feature[0]
        count = 1
        for i in range(1, len(feature)):
            if feature[i] != lasthash:
                self.hash.append(HashEntry(lasthash, count, idflookup.get_count(lasthash), wfactory))
                lasthash = feature[i]
                count = 1
            else:
                count += 1

    def calc_length(self):
        self.length = 0.0
        for i in range(len(self.hash)):
            coeff = self.hash[i].get_coeff()
            self.length += coeff * coeff
            self.hashcount += self.hash[i].get_tf()

    @property
    def length(self):
        return self.length

    def compare(self, op2, data):
        iter1 = 0
        enditer1 = len(self.hash)
        iter2 = 0
        enditer2 = len(op2.hash)

        res = 0.0
        intersectcount = 0
        hash1 = self.hash[iter1].get_hash()
        hash2 = op2.hash[iter2].get_hash()

        while (iter1 != enditer1) and (iter2 != enditer2):
            if hash1 == hash2:
                res += min(self.hash[iter1].get_coeff(), op2.hash[iter2].get_coeff()) ** 2
                intersectcount += self.hash[iter1].get_tf()
                iter1 += 1
                iter2 += 1
            elif hash1 < hash2 + (0x80000000):
                iter1 += 1
            else:
                iter2 += 1

        data.dotproduct = res
        if enditer1 != len(self.hash) or enditer2 != len(op2.hash):
            while iter1 != enditer1:
                self.hash[iter1].get_coeff()
                iter1 += 1
            while iter2 != enditer2:
                op2.hash[iter2].get_coeff()
                iter2 += 1

        data.intersectcount = intersectcount
        data.acount = self.hashcount
        data.bcount = op2.hashcount

    def compare_counts(self, op2, data):
        iter1 = 0
        enditer1 = len(self.hash)
        iter2 = 0
        enditer2 = len(op2.hash)

        intersectcount = 0
        hash1 = self.hash[iter1].get_hash()
        hash2 = op2.hash[iter2].get_hash()

        while (iter1 != enditer1) and (iter2 != enditer2):
            if hash1 == hash2:
                t1 = self.hash[iter1].get_tf()
                t2 = op2.hash[iter2].get_tf()
                intersectcount += min(t1, t2)
                iter1 += 1
                iter2 += 1

        data.intersectcount = intersectcount
        data.acount = self.hashcount
        data.bcount = op2.hashcount

    def compare_detail(self, op2, buf):
        a_only = []
        b_only = []
        ab_both = []

        res = 0.0
        iter1 = 0
        enditer1 = len(self.hash)
        iter2 = 0
        enditer2 = len(op2.hash)

        while (iter1 != enditer1) and (iter2 != enditer2):
            if self.hash[iter1].get_hash() == op2.hash[iter2].get_hash():
                ab_both.append(self.hash[iter1])
                ab_both.append(op2.hash[iter2])
                t1 = self.hash[iter1].get_tf()
                t2 = op2.hash[iter2].get_tf()
                if t1 < t2:
                    res += min(t1, 0.5) ** 2
                    intersectcount = t1
                else:
                    res += min(t2, 0.5) ** 2
                    intersectcount = t2
                iter1 += 1
                iter2 += 1

        while iter1 != enditer1:
            a_only.append(self.hash[iter1])
            iter1 += 1

        while iter2 != enditer2:
            b_only.append(op2.hash[iter2])
            iter2 += 1

        buf.write("lena=" + str(self.length) + "\n")
        buf.write("lenb=" + str(op2.length()) + "\n")

        res /= (self.length * op2.length())

        write_only_list(a_only, buf)
        buf.write("\n")
        write_both_list(ab_both, buf)
        buf.write("\n")
        write_only_list(b_only, buf)

    def get_length(self):
        return self.length

    @property
    def length(self):
        return self.length

    def restore_xml(self, parser, wfactory, idflookup):
        if not idflookup.empty():
            while parser.peek().is_start():
                entry = HashEntry()
                self.hash.append(entry)
                entry.restore_xml(parser, wfactory, idflookup)

    @property
    def length(self):
        return self.length

    def restore_sql(self, sql, wfactory, idflookup) -> None:
        if len(sql) < 2:
            raise IOException("Empty lshvector SQL")

        char tok = sql[1]
        start = 1
        while True:
            entry = HashEntry()
            self.hash.append(entry)
            start = entry.restore_sql(sql, start, wfactory, idflookup)

    def restore_base64(self, input: Reader, buffer: list[int], encoder: int) -> None:
        if len(self.hash) == 0:
            return

        charBuf = [70] * 7
        i = 0
        for _ in range(len(self.hash)):
            entry = HashEntry()
            self.hash.append(entry)
            i += 1
