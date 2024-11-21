Here is the translation of the given Java code into equivalent Python:

```Python
class WeightFactory:
    def __init__(self):
        self.idfweight = [0] * 512  # Weights associated with (normalized) idf counts
        self.tfweight = [0] * 64  # Weights associated with tf (term frequency) counts
        self.weightnorm = -1.0  # Scale to which idf weights are normalized = -log2( probability of 1000th most common hash)
        self.probflip0 = 0.0  # Hash flipping probability in causal model, param0
        self.probflip1 = 0.0  # Hash flipping probability in causal model, param1
        self.probdiff0 = 0.0  # Hash addition/removal probability, param0
        self.probdiff1 = 0.0  # Hash addition/removal probability, param1
        self.scale = 1.0  # Final scaling to all weights
        self.addend = 0.0  # Final correction to score

    def update_norms(self):
        self.probflip0_ norm = self.probflip0 * self.scale
        self.probflip1_ norm = self.probflip1 * self.scale
        self.probdiff0_ norm = self.probdiff0 * self.scale
        self.probdiff1_ norm = self.probdiff1 * self.scale

    def get_idf_size(self):
        return len(self.idfweight)

    def get_tf_size(self):
        return len(self.tfweight)

    def get_size(self):
        return len(self.idfweight) + len(self.tfweight) + 7

    def get_idf_weight(self, val: int):
        return self.idfweight[val]

    def get_tf_weight(self, val: int):
        return self.tfweight[val]

    def get_coeff(self, i: int, t: int):
        return self.idfweight[i] * self.tfweight[t]

    def get_weight_norm(self):
        return self.weightnorm

    def get_flip_norm0(self):
        return self.probflip0_ norm

    def get_diff_norm0(self):
        return self.probdiff0_ norm

    def get_flip_norm1(self):
        return self.probflip1_ norm

    def get_diff_norm1(self):
        return self.probdiff1_ norm

    def get_scale(self):
        return self.scale

    def get_addend(self):
        return self.addend

    def set_logarithmic_tf_weights(self):
        log2 = math.log(2.0)
        for i in range(len(self.tfweight)):
            self.tfweight[i] = math.sqrt(1 + math.log(i+1) / log2)

    def save_xml(self, fwrite: Writer):
        fwrite.write("<weightfactory scale=\"{}\" addend=\"{}\">\n".format(self.scale, self.addend))
        for element in self.idfweight:
            fwrite.write("  <idf>{}</idf>\n".format(element / math.sqrt(self.scale)))
        for element in self.tfweight:
            fwrite.write("  <tf>{}</tf>\n".format(element))
        fwrite.write("  <weightnorm>{}</weightnorm>\n".format(self.weightnorm * self.scale))
        fwrite.write("  <probflip0>{}</probflip0>\n".format(self.probflip0))
        fwrite.write("  <probflip1>{}</probflip1>\n".format(self.probflip1))
        fwrite.write("  <probdiff0>{}</probdiff0>\n".format(self.probdiff0))
        fwrite.write("  <probdiff1>{}</probdiff1>\n".format(self.probdiff1))
        fwrite.write("</weightfactory>\n")

    def to_array(self):
        num_rows = self.get_size()
        res = [0] * num_rows
        scale_sqrt = math.sqrt(self.scale)

        for i in range(len(self.idfweight)):
            res[i] = self.idfweight[i] / scale_sqrt

        for i in range(len(self.tfweight)):
            res[len(self.idfweight) + i] = self.tfweight[i]

        res[num_rows - 7] = self.weightnorm * self.scale
        res[num_rows - 6] = self.probflip0
        res[num_rows - 5] = self.probflip1
        res[num_rows - 4] = self.probdiff0
        res[num_rows - 3] = self.probdiff1
        res[num_rows - 2] = self.scale
        res[num_rows - 1] = self.addend

        return res

    def set(self, weight_array):
        num_rows = len(weight_array)
        if num_rows != self.get_size():
            raise ValueError("Not enough values in double array")
        self.scale = weight_array[-2]
        self.addend = weight_array[-1]
        self.weightnorm = weight_array[-7] / self.scale
        self.probflip0 = weight_array[-6]
        self.probflip1 = weight_array[-5]
        self.probdiff0 = weight_array[-4]
        self.probdiff1 = weight_array[-3]

        sqrt_scale = math.sqrt(self.scale)
        for i in range(len(self.idfweight)):
            self.idfweight[i] = weight_array[i] * sqrt_scale

        for i in range(len(self.tfweight)):
            self.tfweight[i] = weight_array[len(self.idfweight) + i]
        
        self.update_norms()

    def restore_xml(self, parser):
        el = parser.start("weightfactory")
        scale = float(el.getAttribute("scale"))
        addend = float(el.getAttribute("addend"))

        for _ in range(len(self.idfweight)):
            parser.start("idf")
            val = float(parser.end().getText())
            self.idfweight[_] = val * math.sqrt(scale)

        for i in range(len(self.tfweight)):
            parser.start("tf")
            val = float(parser.end().getText())
            self.tfweight[i] = val

        parser.start("weightnorm")
        weightnorm = float(parser.end().getText())

        parser.start("probflip0")
        probflip0 = float(parser.end().getText())

        parser.start("probflip1")
        probflip1 = float(parser.end().getText())

        parser.start("probdiff0")
        probdiff0 = float(parser.end().getText())

        parser.start("probdiff1")
        probdiff1 = float(parser.end().getText())
        
        parser.end(el)
        self.update_norms()
```

Note that Python does not have direct equivalent of Java's `Math.sqrt()` and `Math.log()`. We use the built-in functions from math module for these operations.