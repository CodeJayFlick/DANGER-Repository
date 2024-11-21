Here is the translation of the Java code into equivalent Python:

```Python
class ArrayMethods:
    ARRAY_REF = "arrayref"
    CLASS_NAME = "className"
    DIMENSION = "dim"
    MULTIANEWARRAY = "multianewarrayOp"
    PROCESS_ADDITIONAL_DIMENSIONS = "multianewarrayProcessAdditionalDimensionsOp"
    MAX_PCODE_OP_ARGS = 7

    def __init__(self):
        pass

    @staticmethod
    def get_pcode_for_multi_anew_array(pCode, constant_pool_index, constant_pool, dimensions):
        for i in range(dimensions, 0, -1):
            pCode.emit_pop_cat1_value(f"{ArrayMethods.DIMENSION}{i}")
        
        pCode.emit_assign_varnode_from_pcode_op_call(ArrayMethods.CLASS_NAME, 4,
                                                       "ConstantPoolJava.CPOOL_MULTIANEWARRAY", 
                                                       str(constant_pool_index), 
                                                       ConstantPoolJava.CPOOL_OP)

        if dimensions > ArrayMethods.MAX_PCODE_OP_ARGS - 1:
            multianewarrayOpArgs = [ArrayMethods.CLASS_NAME]
            for i in range(1, ArrayMethods.MAX_PCODE_OP_ARGS):
                multianewarrayOpArgs.append(f"{ArrayMethods.DIMENSION}{i}")
        else:
            multianewarrayOpArgs = [ArrayMethods.CLASS_NAME]
            for i in range(1, dimensions + 1):
                multianewarrayOpArgs.append(f"{ArrayMethods.DIMENSION}{i}")

        pCode.emit_assign_varnode_from_pcode_op_call(ArrayMethods.ARRAY_REF, 4,
                                                       ArrayMethods.MULTIANEWARRAY, 
                                                       ArrayMethods.CLASS_NAME, "dim1", "dim2")

        for i in range(max(dimensions + 1, ArrayMethods.MAX_PCODE_OP_ARGS), dimensions + 1):
            pCode.emit_void_pcode_op_call(ArrayMethods.PROCESS_ADDITIONAL_DIMENSIONS,
                                           [ArrayMethods.ARRAY_REF, f"{ArrayMethods.DIMENSION}{i}"])

        pCode.emit_push_cat1_value(ArrayMethods.ARRAY_REF)

    @staticmethod
    def get_primitive_array_token(code):
        if code == JavaClassConstants.T_BOOLEAN:
            return "boolean"
        elif code == JavaClassConstants.T_CHAR:
            return "char"
        elif code == JavaClassConstants.T_FLOAT:
            return "float"
        elif code == JavaClassConstants.T_DOUBLE:
            return "double"
        elif code == JavaClassConstants.T_BYTE:
            return "byte"
        elif code == JavaClassConstants.T_SHORT:
            return "short"
        elif code == JavaClassConstants.T_INT:
            return "int"
        elif code == JavaClassConstants.T_LONG:
            return "long"
        else:
            raise ValueError(f"Invalid primitive type code: {code}")

    @staticmethod
    def get_array_base_type(i, dt_manager):
        if i == JavaClassConstants.T_BOOLEAN:
            return "Z", dt_manager
        elif i == JavaClassConstants.T_CHAR:
            return "C", dt_manager
        elif i == JavaClassConstants.T_FLOAT:
            return "F", dt_manager
        elif i == JavaClassConstants.T_DOUBLE:
            return "D", dt_manager
        elif i == JavaClassConstants.T_BYTE:
            return "B", dt_manager
        elif i == JavaClassConstants.T_SHORT:
            return "S", dt_manager
        elif i == JavaClassConstants.T_INT:
            return "I", dt_manager
        elif i == JavaClassConstants.T_LONG:
            return "J", dt_manager
        else:
            raise ValueError(f"Invalid primitive type code: {i}")
```

Note that Python does not have direct equivalent of Java's `switch` statement. Instead, we use if-elif ladder to achieve the same functionality.