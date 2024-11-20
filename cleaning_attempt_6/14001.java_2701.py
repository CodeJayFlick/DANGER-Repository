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
