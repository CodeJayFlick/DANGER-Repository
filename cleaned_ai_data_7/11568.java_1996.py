class OpBehaviorOther:
    def evaluate(self, emu: object, out: object = None, inputs: list = []) -> None:
        """
        Evaluate the CALLOTHER op which corresponds to this behavior.

        Args:
            emu (object): emulator which contains associated memory state
            out (object, optional): output varnode or null if no assignment has been made. Defaults to None.
            inputs (list, optional): input varnodes passed as parameters to this pcodeop. The inputs[0] value corresponds to the index value of this pcodeop and can generally be ignored. The inputs[1] value corresponds to the first (leftmost) parameter passed to this pcodeop within the language implementation. Defaults to [].
        """
