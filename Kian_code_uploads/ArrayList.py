class ArrayList:
    list = []
    num_elements = 0

    def is_empty(self):
        return self.num_elements == 0

    def size(self):
        return self.num_elements

    def get(self, location):
        try:
            return self.list[location]
        except IndexError:
            print('Invalid index')

    def insert(self, item, location):
        if location < 0 or location > self.num_elements:
            print('Index out of bounds')
        else:
            self.list.append(0)
            self.num_elements += 1
            for i in range(self.num_elements, location):
                self.list[i] = self.list[i - 1]
            self.list[location] = item

    def remove(self, location):
        if self.num_elements == 0:
            print('List is empty, nothing to remove')
        else:
            temp = self.list[location]
            for i in range(location, self.num_elements - 1):
                self.list[i] = self.list[i + 1]
            self.num_elements -= 1
            return temp

    def remove_all(self):
        self.list = []
        self.num_elements = 0

    def __str__(self):
        return_string = ''
        for i in self.list:
            return_string += str(i) + ' '
        return return_string
