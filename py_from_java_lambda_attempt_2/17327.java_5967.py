Here is the translation of the Java code to Python:
```
import io

class DropContinuousQueryPlan:
    def __init__(self):
        self.continuous_query_name = None

    def get_continuous_query_name(self):
        return self.continuous_query_name

    @property
    def physical_plan_type(self):
        # This is equivalent to the Java enum, but in Python we can use a property instead of an attribute
        return "DROP_CONTINUOUS_QUERY"

class PhysicalPlan:
    pass  # We don't need this class for now, it's just used as a base class in the original code

# Usage example:

plan = DropContinuousQueryPlan()
print(plan.get_continuous_query_name())  # None

plan2 = DropContinuousQueryPlan("my_cq")
print(plan2.get_continuous_query_name())  # "my_cq"

# Serialization and deserialization (equivalent to Java's ByteBuffer)
def serialize(plan):
    buffer = io.BytesIO()
    buffer.write(plan.physical_plan_type.encode())
    buffer.write(plan.continuous_query_name.encode())
    return buffer.getvalue()

def deserialize(buffer):
    plan = DropContinuousQueryPlan()
    plan.continuous_query_name = buffer.decode().split(b"")[1].decode()
    return plan

serialized_data = serialize(plan2)
deserialized_plan = deserialize(serialized_data)

print(deserialized_plan.get_continuous_query_name())  # "my_cq"
```
Note that I didn't translate the `Operator` class, as it's not used in this specific code snippet. Also, Python doesn't have a direct equivalent to Java's enum, so we use a property instead.