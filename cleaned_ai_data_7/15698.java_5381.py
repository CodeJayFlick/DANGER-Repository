class SimpleCompositeLoss:
    def __init__(self):
        self.components = []
        self.indices = []

    def add_loss(self, loss=None, index=None):
        if loss is not None and index is not None:
            self.components.append(loss)
            self.indices.append(index)
        elif loss is not None:
            self.components.append(loss)
            self.indices.append(None)

    def input_for_component(self, component_index: int, labels: list, predictions: list) -> tuple:
        if self.indices[component_index] is not None:
            index = self.indices[component_index]
            return (labels[index], predictions[index]),  # Return a tuple of two elements
        else:
            return (labels, predictions),  # Return a tuple of two elements

# Example usage:

loss1 = SimpleCompositeLoss()
loss2 = loss1.add_loss(loss="Loss 1")
loss3 = loss1.add_loss(loss="Loss 2", index=0)

print(loss1.components)  # Output: ['Loss 1', 'Loss 2']
print(loss1.indices)     # Output: [None, 0]
