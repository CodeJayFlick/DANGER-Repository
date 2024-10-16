import json

class Task:
    def __init__(self, title, description):
        self.title = title
        self.description = description
        self.completed = False

    def mark_completed(self):
        self.completed = True

    def edit(self, title=None, description=None):
        if title:
            self.title = title
        if description:
            self.description = description

    def to_dict(self):
        return {
            "title": self.title,
            "description": self.description,
            "completed": self.completed
        }

class TaskManager:
    def __init__(self):
        self.tasks = []

    def add_task(self, title, description):
        task = Task(title, description)
        self.tasks.append(task)
        print(f'Task "{title}" added.')

    def edit_task(self, task_index, title=None, description=None):
        if 0 <= task_index < len(self.tasks):
            self.tasks[task_index].edit(title, description)
            print(f'Task {task_index + 1} updated.')
        else:
            print("Invalid task index.")

    def delete_task(self, task_index):
        if 0 <= task_index < len(self.tasks):
            task = self.tasks.pop(task_index)
            print(f'Task "{task.title}" deleted.')
        else:
            print("Invalid task index.")

    def mark_completed(self, task_index):
        if 0 <= task_index < len(self.tasks):
            self.tasks[task_index].mark_completed()
            print(f'Task "{self.tasks[task_index].title}" marked as completed.')
        else:
            print("Invalid task index.")

    def list_tasks(self):
        if not self.tasks:
            print("No tasks available.")
            return

        for idx, task in enumerate(self.tasks, 1):
            status = "Completed" if task.completed else "Pending"
            print(f"{idx}. {task.title} - {status}\n   {task.description}")

    def save_tasks(self, filename='tasks.json'):
        with open(filename, 'w') as file:
            json.dump([task.to_dict() for task in self.tasks], file)
        print(f"Tasks saved to {filename}.")

    def load_tasks(self, filename='tasks.json'):
        try:
            with open(filename, 'r') as file:
                tasks_data = json.load(file)
                self.tasks = [Task(t['title'], t['description']) for t in tasks_data]
                for i, task in enumerate(tasks_data):
                    if task['completed']:
                        self.tasks[i].mark_completed()
            print(f"Tasks loaded from {filename}.")
        except FileNotFoundError:
            print(f"No saved task file found: {filename}.")

def main():
    task_manager = TaskManager()
    
    while True:
        print("\nTask Manager:")
        print("1. Add Task")
        print("2. Edit Task")
        print("3. Delete Task")
        print("4. Mark Task as Completed")
        print("5. List Tasks")
        print("6. Save Tasks")
        print("7. Load Tasks")
        print("8. Exit")

        choice = input("Choose an option: ")

        if choice == '1':
            title = input("Enter task title: ")
            description = input("Enter task description: ")
            task_manager.add_task(title, description)

        elif choice == '2':
            task_manager.list_tasks()
            task_index = int(input("Enter task number to edit: ")) - 1
            new_title = input("Enter new title (or press Enter to skip): ")
            new_description = input("Enter new description (or press Enter to skip): ")
            task_manager.edit_task(task_index, title=new_title, description=new_description)

        elif choice == '3':
            task_manager.list_tasks()
            task_index = int(input("Enter task number to delete: ")) - 1
            task_manager.delete_task(task_index)

        elif choice == '4':
            task_manager.list_tasks()
            task_index = int(input("Enter task number to mark as completed: ")) - 1
            task_manager.mark_completed(task_index)

        elif choice == '5':
            task_manager.list_tasks()

        elif choice == '6':
            task_manager.save_tasks()

        elif choice == '7':
            task_manager.load_tasks()

        elif choice == '8':
            print("Exiting Task Manager.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
