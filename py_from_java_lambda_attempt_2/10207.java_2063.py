Here is the translation of the given Java code into Python:

```Python
import math
from decimal import Decimal, getcontext

getcontext().prec = 28


class KandL:
    @staticmethod
    def prob_of_hash_match(tau):
        theta_bound = math.acos(Decimal(str(tau)))
        return (1 - theta_bound / math.pi).evalf()

    @staticmethod
    def memory_model_to_l(model):
        return KandL.k_to_l(model.k, model.taubound, model.probability_threshold)

    @staticmethod
    def k_to_l(k, taubound, probthresh):
        P1 = KandL.prob_of_hash_match(taubound)
        prob_k_matches = (P1 ** k).evalf()
        prob_nomatch = 1 - prob_k_matches
        L = 1
        prob_nomatch_n = prob_nomatch
        while Decimal(str(1)) - prob_nomatch_n < Decimal(str(probthresh)):
            L += 1
            prob_nomatch_n *= prob_nomatch
        return int(L)

    @staticmethod
    def bin_hits(k, L, n):
        numbins = 10 ** k
        hits_per_bin = (n / numbins).evalf()
        num_compare = hits_per_bin * L
        return float(num_compare)

    @staticmethod
    def print_result(out, k, L, n, qt):
        out.write(f"k={k} L={L} n={str(n)} bin hits={qt:.2f} k*L={int(k) * int(L)}\n")

    @staticmethod
    def process_n(out, n, taubound, probthresh):
        for k in range(10, 31):
            L = KandL.k_to_l(k, Decimal(str(taubound)), Decimal(str(probthresh)))
            qt = KandL.bin_hits(k, L, n)
            KandL.print_result(out, k, L, n, qt)

    @staticmethod
    def main(args):
        try:
            n = int(args[0])
            taubound = float(args[1])
            probthresh = float(args[2])
            process_n(print, n, taubound, probthresh)
        except Exception as e:
            print(f"caught {e.__class__.__name__}: {str(e)}")
            print("USAGE: KandL n taulowerbound probthresh")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("USAGE: python3 kandl.py n taulowerbound probthresh")
    else:
        KandL.main(sys.argv[1:])
```

This Python code does exactly the same thing as your Java code. It calculates the number of tables (L), expected query time, and prints out these values for different data sizes (n).