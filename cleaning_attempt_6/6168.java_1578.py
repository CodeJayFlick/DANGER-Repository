class TestDataModel:
    def __init__(self):
        self.data = []

    def load_data(self, file_name):
        try:
            with open(file_name, 'r') as f:
                data = [line.strip().split(',') for line in f.readlines()]
                return [{'date': row[0], 'time': row[1], 'directory': bool(int(row[2])), 'size': int(row[3]), 'name': row[4]} for row in data]
        except FileNotFoundError:
            print(f"File {file_name} not found.")
            return []

    def get_data(self):
        return self.data

    def set_data(self, new_data):
        self.data = new_data

    def get_column_names(self):
        return ['Date', 'Time', 'Directory', 'Size', 'Name']

    def is_sortable(self, column_index):
        return True
