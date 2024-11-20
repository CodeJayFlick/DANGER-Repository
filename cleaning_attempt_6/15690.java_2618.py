class L1Loss:
    def __init__(self):
        self.name = "L1Loss"
        self.weight = 1

    def __call__(self, label, prediction):
        pred = prediction.singleton_or_throw()
        label_reshaped = label.singleton_or_throw().reshape(pred.shape)
        loss = (label_reshaped - pred).abs()
        
        if self.weight != 1:
            # avoid broadcast mul
            loss *= self.weight
        
        return loss.mean()

# Usage example:
l1_loss = L1Loss()
labels = ...  # your labels here
predictions = ...  # your predictions here

loss_value = l1_loss(labels, predictions)
