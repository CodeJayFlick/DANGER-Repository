class Batchifier:
    STACK = "stack"

    @staticmethod
    def from_string(name):
        if name == BATCHIFIER_STACK:
            return StackBatchifier()
        elif name == "none":
            return None
        else:
            raise ValueError("Invalid batchifier name")

    def batchify(self, inputs: list) -> NDList:
        # Implement your logic here to convert an array of NDLists into a single NDList.
        pass

    def unbatchify(self, input_list: NDList) -> list:
        # Implement your logic here to reverse the batchify operation and return an array of NDLists.
        pass


class StackBatchifier(Batchifier):
    @staticmethod
    def from_string(name):
        if name == BATCHIFIER_STACK:
            return StackBatchifier()
        else:
            raise ValueError("Invalid batchifier name")

    def batchify(self, inputs: list) -> NDList:
        # Implement your logic here to convert an array of NDLists into a single NDList.
        pass

    def unbatchify(self, input_list: NDList) -> list:
        # Implement your logic here to reverse the batchify operation and return an array of NDLists.
        pass


class NDList(list):
    pass
