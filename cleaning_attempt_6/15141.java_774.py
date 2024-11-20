import logging
from typing import Dict, List

class StudentRepository:
    def __init__(self, student_database: 'StudentDatabase', context: Dict[str, List['Student']]):
        self.student_database = student_database
        self.context = context

    @logging.getLogger().info("Registering {} for insert in context.")
    def register_new(self, student: 'Student'):
        self.register(student, "INSERT")

    @logging.getLogger().info("Registering {} for modify in context.")
    def register_modified(self, student: 'Student'):
        self.register(student, "MODIFY")

    @logging.getLogger().info("Registering {} for delete in context.")
    def register_deleted(self, student: 'Student'):
        self.register(student, "DELETE")

    def register(self, student: 'Student', operation: str):
        students_to_operate = self.context.get(operation)
        if students_to_operate is None:
            students_to_operate = []
        students_to_operate.append(student)
        self.context[operation] = students_to_operate

    @logging.getLogger().info("Commit started")
    def commit(self):
        if not self.context or len(self.context) == 0:
            return
        logging.info("Commit finished.")
        for operation, students in self.context.items():
            if operation == "INSERT":
                self.commit_insert(students)
            elif operation == "MODIFY":
                self.commit_modify(students)
            elif operation == "DELETE":
                self.commit_delete(students)

    def commit_insert(self, students: List['Student']):
        for student in students:
            logging.info("Saving {} to database.".format(student.name))
            self.student_database.insert(student)

    def commit_modify(self, students: List['Student']):
        for student in students:
            logging.info("Modifying {} to database.".format(student.name))
            self.student_database.modify(student)

    def commit_delete(self, students: List['Student']):
        for student in students:
            logging.info("Deleting {} to database.".format(student.name))
            self.student_database.delete(student)
