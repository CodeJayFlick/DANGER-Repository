class OatClassType:
    k_OAT_CLASS_ALL_COMPILED = 0
    k_OAT_CLASS_SOME_COMPILED = 1
    k_OAT_CLASS_NONE_COMPILATED = 2
    k_OAT_CLASS_MAX = 3

    def __init__(self, value):
        self.value = value

    @staticmethod
    def get_values():
        return [OatClassType(k_OAT_CLASS_ALL_COMPILED),
                OatClassType(k_OAT_CLASS_SOME_COMPILATED),
                OatClassType(k_OAT_CLASS_NONE_COMPILATED),
                OatClassType(k_OAT_CLASS_MAX)]

# Usage:
print(OatClassType.k_OAT_CLASS_ALL_COMPILTED)  # prints: 0
for oat_class_type in OatClassType.get_values():
    print(oat_class_type.value)
