class NDIndexFullPick:
    def __init__(self, indices: 'NDArray', axis: int):
        self.indices = indices
        self.axis = axis

def from_index(index: 'NDIndex', target_shape) -> Optional['NDIndexFullPick']:
    full_pick = None
    for el in index.get_indices():
        if isinstance(el, NDIndexAll):
            pass  # Do nothing as we're just incrementing the axis
        elif isinstance(el, NDIndexPick):
            if full_pick is not None:
                raise UnsupportedOperationException("Only one pick per get is currently supported")
            else:
                full_pick = NDIndexFullPick(el.get_indices(), el.axis)
        else:
            return Optional.empty()  # Invalid dim for fullPick

    return Optional.ofNullable(full_pick)

def get_indices(self) -> 'NDArray':
    return self.indices

def get_axis(self) -> int:
    return self.axis
