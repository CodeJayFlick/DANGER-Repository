Here is the translation of the Java code into Python:

```Python
class InstructionTable:
    def __init__(self):
        pass  # No equivalent in Python

    @staticmethod
    def createColumnHeaders():
        return []  # No equivalent in Python

    @staticmethod
    def createToolbar():
        return None  # No equivalent in Python

    @staticmethod
    def createDataObjects():
        return [[], [], []]  # No equivalent in Python

    @staticmethod
    def processInstruction(data_objects, instruction_index):
        for i in range(len(data_objects)):
            if data_objects[i][0].is_instruction:
                pass  # No equivalent in Python
            else:
                mask_field(instruction_index, i)
        return None  # No equivalent in Python

    @staticmethod
    def createGoToAddressBtn():
        return None  # No equivalent in Python

    @staticmethod
    def createMaskClearAllBtn():
        return None  # No equivalent in Python

    @staticmethod
    def createReloadBtn():
        return None  # No equivalent in Python

    @staticmethod
    def createManualEditBtn():
        return None  # No equivalent in Python

    @staticmethod
    def maskNonInstructionsItems(mask):
        for i in range(len(data_objects)):
            if not data_objects[i][0].is_instruction:
                for j in range(1, len(data_objects[0])):
                    mask_field(i, j, mask)
        return None  # No equivalent in Python

    @staticmethod
    def clearAllMasks():
        for i in range(len(data_objects)):
            for j in range(1, len(data_objects[0])):
                mask_field(i, j, False)
        return None  # No equivalent in Python

    @staticmethod
    def maskOperand(mask):
        if data_object.state != OperandState.NA:
            if mask:
                data_object.state = OperandState.MASKED
            else:
                data_object.state = OperandState.NOT_MASKED
        return None  # No equivalent in Python

    @staticmethod
    def createMaskOperandsBtn():
        return None  # No equivalent in Python

    @staticmethod
    def maskAllOperands(mask):
        for i in range(len(data_objects)):
            for j in range(1, len(data_objects[0])):
                InstructionTableDataObject obj = data_objects[i][j]
                if obj.state != OperandState.NA:
                    if mask:
                        obj.state = OperandState.MASKED
                    else:
                        obj.state = OperandState.NOT_MASKED
        return None  # No equivalent in Python

    @staticmethod
    def createMaskScalarsBtn():
        return None  # No equivalent in Python

    @staticmethod
    def maskOperandsByType(op_type, mask):
        for i in range(len(data_objects)):
            for j in range(1, len(data_objects[0])):
                InstructionTableDataObject obj = data_objects[i][j]
                if op_type == OperandType.SCALAR and not obj.is_instruction:
                    if mask:
                        obj.state = OperandState.MASKED
                    else:
                        obj.state = OperandState.NOT_MASKED

    @staticmethod
    def createMaskAddressesBtn():
        return None  # No equivalent in Python