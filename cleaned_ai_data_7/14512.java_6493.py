class ArrayTransposeWorker:
    def __init__(self, master, id):
        pass  # equivalent to super(master, id)

    def execute_operation(self):
        array_input = self.get_received_data()
        rows = len(array_input.data[0])
        cols = len(array_input.data)
        result_data = [[0 for _ in range(rows)] for _ in range(cols)]
        
        for i in range(cols):
            for j in range(rows):
                # flipping element positions along diagonal
                result_data[j][i] = array_input.data[i][j]
                
        return ArrayResult(result_data)

class Worker:
    pass

class Master:
    pass

class ArrayInput:
    def __init__(self, data):
        self.data = data

class ArrayResult:
    def __init__(self, data):
        self.data = data
