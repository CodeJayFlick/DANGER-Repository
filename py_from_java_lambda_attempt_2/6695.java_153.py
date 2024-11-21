Here is the translation of the given Java code into Python:

```Python
class SequenceDatabase:
    def __init__(self, sequences_to_mine, sequence_length):
        if not isinstance(sequence_length, int) or sequence_length < 1:
            raise ValueError("length must be positive!")
        self.sequence_length = sequence_length

        self.sequences = sequences_to_mine
        self.total_num_seqs = 0

        for seq in sequences_to_mine:
            if len(seq.get_sequence_as_string()) != sequence_length:
                raise ValueError(f"sequence {seq.get_sequence_as_string()} does not have length {sequence_length}")
            self.total_num_seqs += seq.get_count()

    def get_sequence_length(self):
        return self.sequence_length

    def get_sequences(self):
        return self.sequences

    def get_total_num_seqs(self):
        return self.total_num_seqs


class Sequence:
    def __init__(self, sequence_as_string, count):
        self.sequence_as_string = sequence_as_string
        self.count = count

    def get_sequence_as_string(self):
        return self.sequence_as_string

    def get_count(self):
        return self.count


class FrequentSequenceItem:
    def __init__(self, count, item):
        self.count = count
        self.item = item

    def __lt__(self, other):
        if not isinstance(other, FrequentSequenceItem):
            raise TypeError("Can only compare with another FrequentSequenceItem")
        return self.count < other.count


class SequenceItem:
    def __init__(self, item, position):
        self.item = item
        self.position = position

    def __eq__(self, other):
        if not isinstance(other, SequenceItem):
            raise TypeError("Can only compare with another SequenceItem")
        return self.item == other.item and self.position == other.position


def get_globally_frequent_items(self, min_support):
    item_bag = {}
    frequent_item_set = set()

    for seq in self.sequences:
        for i in range(self.sequence_length):
            f_item = SequenceItem(seq.get_sequence_as_string()[i], i)
            count = item_bag.get(f_item)
            if count is None:
                item_bag[f_item] = seq.get_count()
            else:
                item_bag[f_item] = count + seq.get_count()

    for item, count in item_bag.items():
        if count >= min_support:
            frequent_item_set.add(FrequentSequenceItem(count, item))

    return sorted(list(frequent_item_set), key=lambda x: x.count)
```

Please note that Python does not have direct equivalent of Java's `TreeSet` and `Map.Entry`. In this translation, I used a dictionary (`item_bag`) to store the items and their counts. The frequent items are stored in a set (`frequent_item_set`).