class Prime:
    PRIMES = [
        17, 37, 67, 131, 257,
        521, 1031, 2053, 4099, 8209, 16411, 29251, 65537,
        131101, 262147, 524309, 1048583, 2097169, 4194319, 8388617, 16777259,
        33554467, 67108879, 134217757, 268435459, 536870923, 1073741827, 2147483647
    ]

    @staticmethod
    def next_prime(n):
        for prime in Prime.PRIMES:
            if prime > n:
                return prime
        return 0

# Example usage:
print(Prime.next_prime(100))  # Output: 131
