class OpBehaviorIntSdiv:
    def __init__(self):
        super().__init__()

    def evaluate_binary(self, size_out, size_in, in1, in2):
        if in2 == 0:
            raise Exception("Divide by 0")
        
        num = in1  # Convert to signed
        denom = in2
        
        num = self.sign_extend(num, size_in)
        denom = self.sign_extend(denom, size_in)

        sres = num // denom  # Do the signed division

        return self.zero_extend(sres, size_out)  # Cut to appropriate size and recast as unsigned

    def sign_extend(self, value, bits):
        if (value & ((1 << bits - 1) | ~((1 << bits - 1)))) != 0:
            return value | (~((1 << bits - 1)) + (1 << bits - 1))
        else:
            return value

    def zero_extend(self, value, bits):
        mask = ~(~(1 << bits) - 1)
        return value & mask
