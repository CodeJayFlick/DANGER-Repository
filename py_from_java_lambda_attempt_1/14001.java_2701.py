Here is the equivalent Python code:

```Python
class Student:
    def __init__(self, id: int, name: str, grade: str):
        self.id = id
        self.name = name
        self.grade = grade

def test_student_equality():
    first_student = Student(1, "Adam", 'A')
    second_student = Student(2, "Donald", 'B')
    same_second_student = Student(2, "Donald", 'B')

    assert first_student == first_student  # True
    assert first_student != second_student  # True
    assert second_student == same_second_student  # True

if __name__ == "__main__":
    test_student_equality()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we define the function as you would any other function in your program. The last line of code (`test_student_equality()`) is used to call this function when running the script directly (not imported).