class PatternBlock:
    def __init__(self):
        self.offset = 0
        self.nonzerosize = 0
        self.maskvec = []
        self.valvec = []

    def shift(self, sa):
        self.offset += sa
        self.normalize()

    def get_length(self):
        return self.offset + self.nonzerosize

    def always_true(self):
        return self.nonzerosize == 0

    def always_false(self):
        return self.nonzerosize == -1

    def dispose(self):
        pass

    def normalize(self):
        if self.nonzerosize <= 0:
            self.offset = 0
            self.maskvec.clear()
            self.valvec.clear()
            return
        iter1, iter2 = self.maskvec.begin(), self.valvec.begin()
        while not iter1.is_end() and (iter1.get() == 0):
            iter1.increment()
            iter2.increment()
            self.offset += 4
        self.maskvec.erase(self.maskvec.begin(), iter1)
        self.valvec.erase(self.valvec.begin(), iter2)

        if not self.maskvec.empty():
            suboff = 0
            tmp = self.maskvec[0]
            while tmp != 0:
                suboff += 1
                tmp >>= 8
            suboff = 4 - suboff
            if suboff != 0:
                self.offset += suboff
                for i in range(self.maskvec.size() - 1):
                    tmp = self.maskvec[i] << (suboff * 8)
                    tmp |= self.maskvec[i + 1] >> ((4 - suboff) * 8)
                    self.maskvec.set(i, tmp)
                self.valvec.setBack(self.valvec.back() << (suboff * 8))
                for i in range(self.valvec.size() - 1):
                    tmp = self.valvec[i] << (suboff * 8)
                    tmp |= self.valvec[i + 1] >> ((4 - suboff) * 8)
                    self.valvec.set(i, tmp)

        iter1, iter2 = self.maskvec.end(), self.valvec.end()
        while not iter1.is_begin():
            iter1.decrement()
            iter2.decrement()
            if iter1.get() != 0:
                break
        if not iter1.is_end():
            iter1.increment()
            iter2.increment()

        self.maskvec.erase(iter1, self.maskvec.end())
        self.valvec.erase(iter2, self.valvec.end())

    def __init__(self, off, msk, val):
        self.offset = off
        self.maskvec.append(msk)
        self.valvec.append(val)
        self.nonzerosize = 4
        self.normalize()

    def __init__(self, tf):
        if tf:
            self.offset = 0
            self.nonzerosize = 0
        else:
            self.offset = 0
            self.nonzerosize = -1

    def intersect(self, b):
        res = PatternBlock(True)
        maxlength = max(self.get_length(), b.get_length())
        res.offset = 0
        offset1 = 0
        while offset1 < maxlength:
            mask1 = self.get_mask(offset1 * 8, 4 * 8)
            val1 = self.get_value(offset1 * 8, 4 * 8)
            mask2 = b.get_mask(offset1 * 8, 4 * 8)
            val2 = b.get_value(offset1 * 8, 4 * 8)
            commonmask = mask1 & mask2
            if (commonmask & val1) != (commonmask & val2):
                res.nonzerosize = -1
                self.normalize()
                return res

            resmask = mask1 | mask2
            resval = (mask1 & val1) | (mask2 & val2)
            res.maskvec.append(resmask)
            res.valvec.append(resval)
            offset1 += 4
        res.nonzerosize = maxlength
        self.normalize()
        return res

    def specializes(self, op2):
        length = 8 * op2.get_length()
        sbit = 0
        while sbit < length:
            tmplength = length - sbit
            if tmplength > 8 * 4:
                tmplength = 8 * 4
            mask1 = self.get_mask(sbit, tmplength)
            val1 = self.get_value(sbit, tmplength)
            mask2 = op2.get_mask(sbit, tmplength)
            val2 = op2.get_value(sbit, tmplength)

            if (mask1 & mask2) != mask2:
                return False
            if ((mask1 & val1) != (mask2 & val2)):
                return False

            sbit += tmplength
        return True

    def identical(self, op2):
        length = 8 * max(self.get_length(), op2.get_length())
        sbit = 0
        while sbit < length:
            tmplength = length - sbit
            if tmplength > 8 * 4:
                tmplength = 8 * 4

            mask1 = self.get_mask(sbit, tmplength)
            val1 = self.get_value(sbit, tmplength)
            mask2 = op2.get_mask(sbit, tmplength)
            val2 = op2.get_value(sbit, tmplength)

            if mask1 != mask2:
                return False
            if ((mask1 & val1) != (mask2 & val2)):
                return False

            sbit += tmplength
        return True

    def get_mask(self, startbit, size):
        startbit -= 8 * self.offset
        wordnum1 = startbit // (8 * 4)
        shift = startbit % (8 * 4)

        if (wordnum1 < 0) or (wordnum1 >= len(self.maskvec)):
            return 0

        res = self.maskvec[wordnum1]
        res <<= shift
        if wordnum1 != wordnum2:
            tmp = self.maskvec[wordnum2]
            res |= tmp >> ((8 * 4 - shift))

        res >>= (8 * 4 - size)

        return res

    def get_value(self, startbit, size):
        startbit -= 8 * self.offset
        wordnum1 = startbit // (8 * 4)
        shift = startbit % (8 * 4)

        if (wordnum1 < 0) or (wordnum1 >= len(self.valvec)):
            return 0

        res = self.valvec[wordnum1]
        res <<= shift
        if wordnum1 != wordnum2:
            tmp = self.valvec[wordnum2]
            res |= tmp >> ((8 * 4 - shift))

        res >>= (8 * 4 - size)

        return res

    def is_instruction_match(self, pos, off):
        if self.nonzerosize <= 0:
            return self.nonzerosize == 0
        off += self.offset
        for i in range(len(self.maskvec)):
            data = pos.get_instruction_bytes(off, 4)
            if (self.maskvec[i] & data) != self.valvec[i]:
                return False
            off += 4

    def is_context_match(self, pos, off):
        if self.nonzerosize <= 0:
            return self.nonzerosize == 0
        off += self.offset
        for i in range(len(self.maskvec)):
            data = pos.get_context_bytes(off, 4)
            if (self.maskvec[i] & data) != self.valvec[i]:
                return False
            off += 4

    def save_xml(self, s):
        s.write("<pat_block ")
        s.write("offset=\"{}\" ".format(self.offset))
        s.write("nonzero=\"{}\">\n".format(self.nonzerosize))

        for i in range(len(self.maskvec)):
            s.write("   <mask_word mask=\"0x{:X}\" val=\"0x{:X}\"\n".format(Utils.to_unsigned_int_hex(self.maskvec[i]), Utils.to_unsigned_int_hex(self.valvec[i])))

        s.write("</pat_block>\n")

    def restore_xml(self, el):
        self.offset = XmlUtils.decode_unknown_int(el.get_attribute_value("offset"))
        self.nonzerosize = XmlUtils.decode_unknown_int(el.get_attribute_value("nonzero"))

        list = el.get_children()
        iter1 = list.iterator()

        while iter1.has_next():
            subel = (Element)iter1.next()
            mask = XmlUtils.decode_unknown_int(subel.get_attribute_value("mask"))
            val = XmlUtils.decode_unknown_int(subel.get_attribute_value("val"))
            self.maskvec.append(mask)
            self.valvec.append(val)

    def __str__(self):
        sb = StringBuilder()

        for i in range(self.offset):
            sb.write("........ ")

        pos = -1
        for i, (m, v) in enumerate(zip(self.maskvec, self.valvec)):
            if i != 0 or m % 8 == 0:
                sb.write(' ')
            if m < 0:
                if v < 0:
                    sb.append('1')
                else:
                    sb.append('0')
            else:
                sb.append('.')
            m <<= 1
            v <<= 1

        return sb.toString()
