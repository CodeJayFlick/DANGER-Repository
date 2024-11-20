import random

class SequenceSampler:
    def sample(self, dataset):
        class Iterate:
            def __init__(self, dataset):
                self.size = len(dataset)
                self.current = 0

            def hasNext(self):
                return self.current < self.size

            def next(self):
                if not self.hasNext():
                    raise StopIteration
                result = self.current
                self.current += 1
                return result

        return Iterate(dataset)


# Example usage:
class RandomAccessDataset:
    def __init__(self, size):
        self.size = size

    def size(self):
        return self.size


dataset = RandomAccessDataset(10)
sampler = SequenceSampler()
iterator = sampler.sample(dataset)

for _ in range(len(dataset)):
    print(next(iterator))
