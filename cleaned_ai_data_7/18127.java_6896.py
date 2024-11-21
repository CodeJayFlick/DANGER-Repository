import logging

class DoublePrecisionDecoderV1:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.pre_value = 0
        self.flag = False
        self.leading_zero_num = 0
        self.tailing_zero_num = 0

    def read_double(self, buffer):
        if not self.flag:
            try:
                buf = [ReadWriteIOUtils.read(buffer) for _ in range(8)]
                res = sum([x << (i * 8) for i, x in enumerate(buf)])
                self.pre_value = res
                tmp = float(res)
                self.leading_zero_num = len(bin(res)[2:]) - bin(res)[2:].count('0')
                self.tailing_zero_num = len(bin(res)[2:][::-1]) - bin(res)[2:][::-1].count('0')
                self.fill_buffer(buffer)
                self.get_next_value(buffer)
                return tmp
            except Exception as e:
                self.logger.error("DoublePrecisionDecoderV1 cannot read first double number", e)
        else:
            try:
                tmp = float(self.pre_value)
                self.get_next_value(buffer)
                return tmp
            except Exception as e:
                self.logger.error("DoublePrecisionDecoderV1 cannot read following double number", e)
        return float('nan')

    def get_next_value(self, buffer):
        if ReadWriteIOUtils.read(buffer) == 0:
            return

        next_flag2 = ReadWriteIOUtils.read(buffer)

        if not next_flag2:
            # case: '10'
            tmp = 0
            for _ in range(TSFileConfig.VALUE_BITS_LENGTH_64BIT - self.leading_zero_num - self.tailing_zero_num):
                bit = ReadWriteIOUtils.read(buffer) != 0
                tmp |= (1 << (TSFileConfig.VALUE_BITS_LENGTH_64BIT - 1 - self.leading_zero_num - _))
            tmp ^= self.pre_value
            self.pre_value = tmp

        else:
            # case: '11'
            leading_zero_num_tmp = ReadWriteIOUtils.read(buffer, TSFileConfig.LEADING_ZERO_BITS_LENGTH_64BIT)
            len_tmp = ReadWriteIOUtils.read(buffer, TSFileConfig.DOUBLE_VALUE_LENGTH)
            tmp = ReadWriteIOUtils.read_long(buffer, len_tmp) << (TSFileConfig.VALUE_BITS_LENGTH_64BIT - leading_zero_num_tmp - len_tmp)
            tmp ^= self.pre_value
            self.pre_value = tmp

        self.leading_zero_num = len(bin(self.pre_value)[2:]) - bin(self.pre_value)[2:].count('0')
        self.tailing_zero_num = len(bin(self.pre_value)[2:][::-1]) - bin(self.pre_value)[2:][::-1].count('0')

        if float.frombytes((self.pre_value).to_bytes(8, 'little')).isNaN:
            self.is_end = True
