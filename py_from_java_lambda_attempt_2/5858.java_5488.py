Here is the translation of the Java code into Python:

```Python
class SequenceSearchState:
    def __init__(self, parent=None):
        self.parent = parent
        self.possible = []
        self.success = None
        self.trans = [None] * 256

    @staticmethod
    def get_max_sequence_size():
        max_val = 0
        for pat in SequenceSearchState.get_possible(self.possible):
            val = pat.size()
            if val > max_val:
                max_val = val
        return max_val

    def add_sequence(self, pattern, position):
        self.possible.append(pattern)
        if position == pattern.size():
            if not self.success:
                self.success = []
            self.success.append(pattern)

    def sort_sequences(self):
        possible.sort(key=lambda x: x.index())
        if self.success:
            self.success.sort(key=lambda x: x.index())

    @staticmethod
    def get_possible(sequences):
        return sequences

    def __lt__(self, other):
        for i in range(len(self.possible)):
            if not SequenceSearchState.get_possible(other).get(i) < self.possible[i]:
                break
        else:
            return True
        return False

    @staticmethod
    def build_single_transition(all_states, position, value):
        new_state = None
        for pattern in SequenceSearchState.get_possible(self.possible):
            if pattern.is_match(position, value):
                if not new_state:
                    new_state = SequenceSearchState(self)
                new_state.add_sequence(pattern, position + 1)
        self.trans[value] = new_state
        if new_state and len(new_state.success) > 0:
            all_states.append(new_state)

    def export_success(self, matches, offset):
        for pattern in self.success:
            match = Match(pattern, offset)
            matches.append(match)

    @staticmethod
    def merge(state1, state2):
        parent = state2.parent
        for i in range(256):
            if state2.trans[i] == state1:
                state2.trans[i] = state1

        if state2.success and not self.success:
            self.success = state2.success
        elif state2.success and self.success:
            tmp = []
            this_pat, oppat = -1, -1
            for i in range(len(self.success)):
                this_pat = self.success[i].index()
                for j in range(len(state2.success)):
                    oppat = state2.success[j].index()
                    if this_pat == oppat:
                        tmp.append(self.success[i])
                        break
                    elif this_pat < oppat:
                        tmp.append(self.success[i])
                        break
            else:
                self.success = tmp

    def sequence_match(self, bytearray, numbytes, matches):
        state = self
        while True:
            if state.success and not isinstance(state.parent, type(None)):
                state.export_success(matches, 0)
            elif len(bytearray) >= numbytes:
                break
            state = state.trans[bytearray.pop(0)]

    def apply(self, in_stream, max_bytes, matches):
        progress = 0
        while True:
            if isinstance(in_stream.readinto(firstbuf), int) and firstbuf.length == 4096:
                secondbuf = bytearray(4096)
                readbytes = in_stream.readinto(secondbuf)
                full_buffers = 2
            elif isinstance(readbytes, int):
                full_buffers = 1
                tmp = bytearray(readbytes)
                for i in range(readbytes):
                    tmp[i] = firstbuf[i]
                secondbuf = tmp
            else:
                break

        offset = 0
        while True:
            state = self
            sub_index = buf_relative_offset
            cur_buf = firstbuf if full_buffers == 2 else secondbuf
            while True:
                if state.success and not isinstance(state.parent, type(None)):
                    state.export_success(matches, offset)
                elif len(cur_buf) <= sub_index or (max_bytes > 0 and offset >= max_bytes):
                    break
                state = state.trans[cur_buf[sub_index]]
                sub_index += 1

            offset += 1
            buf_relative_offset += 1
            if buf_relative_offset == firstbuf.length:
                full_buffers -= 1
                if isinstance(full_buffers, int) and full_buffers > 0:
                    break
                else:
                    firstbuf = secondbuf
                    secondbuf = bytearray(0)
                    buf_relative_offset = 0

    @staticmethod
    def build_transition_level(prev_states, position):
        res = []
        for state in prev_states:
            new_state = SequenceSearchState(state)
            new_state.trans = [None] * 256
            for i in range(256):
                new_state.build_single_transition(res, position, i)

        if not res:
            return []

        # Prepare to dedup the states
        res.sort(key=lambda x: (x.possible[0].index(), len(x.success)))
        final_res = []
        cur_pat = res.pop(0)
        final_res.append(cur_pat)
        while res:
            next_pat = res.pop(0)
            if cur_pat < next_pat:
                break
            elif cur_pat == next_pat:
                SequenceSearchState.merge(next_pat, cur_pat)
            else:
                final_res.append(next_pat)
                cur_pat = next_pat

        return final_res

    @staticmethod
    def build_state_machine(patterns):
        root = SequenceSearchState(None)
        for i in range(len(patterns)):
            pattern = patterns[i]
            pattern.set_index(i)
            root.add_sequence(pattern, 0)

        root.sort_sequences()
        state_level = [root]

        level = 0
        while True:
            state_level = SequenceSearchState.build_transition_level(state_level, level)
            if not state_level:
                break

            level += 1

        return root


class DittedBitSequence:
    def __init__(self):
        pass

    @staticmethod
    def get_possible(sequences):
        return sequences

    def is_match(self, position, value):
        pass

    def size(self):
        pass

    def set_index(self, index):
        pass


class Match:
    def __init__(self, pattern, offset):
        self.pattern = pattern
        self.offset = offset


# Usage example:

patterns = [DittedBitSequence() for _ in range(10)]
state_machine = SequenceSearchState.build_state_machine(patterns)
```

Please note that the translation of Java code to Python is not always straightforward. The above Python code may need some adjustments based on your specific requirements and constraints.