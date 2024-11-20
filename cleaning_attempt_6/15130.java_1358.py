import logging
from typing import List

class Cell:
    def __init__(self):
        self.positionX = 0
        self.positionY = 0
        self.candy = None

class CandyGame:
    def __init__(self, num: int, pool):
        self.cells = [[Cell() for _ in range(num)] for _ in range(num)]
        self.pool = pool
        self.totalPoints = 0
        for i in range(num):
            for j in range(num):
                cell = self.pool.get_new_cell()
                cell.positionX = j
                cell.positionY = i
                self.cells[i][j] = cell

    def print_game_status(self):
        logging.info("")
        for row in self.cells:
            for cell in row:
                candy_name = cell.candy.name
                if len(candy_name) < 20:
                    total_spaces = 20 - len(candy_name)
                    logging.info(" " * (total_spaces // 2) + candy_name + " " * (total_spaces - total_spaces // 2) + "|")
                else:
                    logging.info(candy_name + "|")
            logging.info("")
        logging.info("")

    def adjacent_cells(self, y: int, x: int):
        adjacent = []
        if y == 0:
            adjacent.append(self.cells[1][x])
        if x == 0:
            adjacent.append(self.cells[y][1])
        if y == len(self.cells) - 2:
            adjacent.append(self.cells[len(self.cells) - 1][x])
        if x == len(self.cells) - 2:
            adjacent.append(self.cells[y][len(self.cells) - 1])
        if y > 0 and y < len(self.cells) - 1:
            adjacent.extend([self.cells[y-1][x], self.cells[y+1][x]])
        if x > 0 and x < len(self.cells) - 1:
            adjacent.extend([self.cells[y][x-1], self.cells[y][x+1]])
        return adjacent

    def continue_round(self):
        for i in range(len(self.cells)):
            if self.cells[-1][i].candy.type == "REWARD_FRUIT":
                return True
        for i in range(len(self.cells)):
            for j in range(len(self.cells[0])):
                if not self.cells[i][j].candy.type == "REWARD_FRUIT":
                    adj = self.adjacent_cells(i, j)
                    for cell in adj:
                        if self.cells[i][j].candy.name == cell.candy.name:
                            return True
        return False

    def handle_change(self, points):
        logging.info("+" + str(points) + " points!")
        self.totalPoints += points
        self.print_game_status()

    def round(self, time_so_far: int, total_time: int):
        start = logging.getLogger().getEffectiveLevel()
        end = 0
        while (end - start + time_so_far < total_time and self.continue_round()):
            for i in range(len(self.cells)):
                points = 0
                j = len(self.cells) - 1
                while self.cells[j][i].candy.type == "REWARD_FRUIT":
                    points = self.cells[j][i].candy.points
                    self.cells[j][i].crush(self.pool, self.cells)
                    self.handle_change(points)
            for i in range(len(self.cells)):
                j = len(self.cells) - 1
                while j > 0:
                    points = self.cells[j][i].interact(self.cells[j-1][i], self.pool, self.cells)
                    if points != 0:
                        self.handle_change(points)
                    else:
                        j -= 1
            for row in self.cells:
                j = len(row) - 1
                while j > 0:
                    points = row[j].interact(row[j-1], self.pool, self.cells)
                    if points != 0:
                        self.handle_change(points)
                    else:
                        j -= 1
            end = logging.getLogger().getEffectiveLevel()
