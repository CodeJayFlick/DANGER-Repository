import unittest

class DataMapperTest(unittest.TestCase):
    def test_first_data_mapper(self):
        # Create new data mapper of first type
        from student_data_mapper import StudentDataMapperImpl as Mapper
        mapper = Mapper()

        # Create new student
        student_id = 1
        name = "Adam"
        grade = 'A'
        student = {"studentId": student_id, "name": name, "grade": grade}

        # Add student to database
        mapper.insert(student)

        # Check if student is added in db
        self.assertEqual(student_id, mapper.find(student_id).get()["studentId"])

        # Update existing student object
        updated_name = "AdamUpdated"
        student["name"] = updated_name

        # Update student in database
        mapper.update(student)

        # Check if student is updated in db
        self.assertEqual(updated_name, mapper.find(student_id).get()["name"])

        # Delete student from database
        mapper.delete(student)

        # Result should be false
        self.assertFalse(mapper.find(student_id).is_present())

if __name__ == "__main__":
    unittest.main()
