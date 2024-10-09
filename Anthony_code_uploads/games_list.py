import game

import os
import csv

class GamesList:
    def __init__(self, gamesListPath):
        self.gamesListPath = gamesListPath
    
    def archiveGame(self, game):
        csvfile = open(self.gamesListPath, 'a')
        csvwriter = csv.writer(csvfile, delimiter=",")
        csvwriter.writerow(["archive", game])
        csvfile.close()

    def restoreGame(self, game):
        csvfile = open(self.gamesListPath, 'a')
        csvwriter = csv.writer(csvfile, delimiter=",")
        csvwriter.writerow(["restore", game])
        csvfile.close()

    def deleteGame(self, game):
        csvfile = open(self.gamesListPath, 'a')
        csvwriter = csv.writer(csvfile, delimiter=",")
        csvwriter.writerow(["delete", game])
        csvfile.close()

    def createGame(self, gameName: str, gameLink: str):
        gameObject = game.Game(gameLink, getPosts=False)
        gameObject.toCSV(gameName + ".csv")
        csvfile = open(self.gamesListPath, 'a')
        csvwriter = csv.writer(csvfile, delimiter=",")
        csvwriter.writerow(["create", gameName])
        csvfile.close()

    def compressCSV(self):
        createdGames, archivedGames = self.getCreatedAndArchivedGames()
        csvfile = open(self.gamesListPath, 'w')
        csvwriter = csv.writer(csvfile, delimiter=",")
        for game in createdGames:
            csvwriter.writerow(["create", game])
        for game in archivedGames:
            csvwriter.writerow(["create", game])
            csvwriter.writerow(["archive", game])
        csvfile.close()

    def recreateGame(self, gameName: str, getPosts=True):
        return game.fromFiles(gameName + ".csv", gameName + ".json", includePosts=getPosts)

    def gameExists(self, game: str):
        game = game.lower()
        createdGames, archivedGames = self.getCreatedAndArchivedGames()
        return game in createdGames or game in archivedGames
    
    def gameIsActive(self, game: str):
        game = game.lower()
        createdGames, archivedGames = self.getCreatedAndArchivedGames()
        return game in createdGames

    def gameIsArchived(self, game: str):
        game = game.lower()
        createdGames, archivedGames = self.getCreatedAndArchivedGames()
        return game in archivedGames
    
    def getCreatedAndArchivedGames(self):
        createdGames = set()
        archivedGames = set()
        csvfile = open(self.gamesListPath, 'r')
        csvreader = csv.reader(csvfile, delimiter=",")
        for row in csvreader:
            if row == []:
                pass
            elif row[0] == "create":
                createdGames.add(row[1])
            elif row[0] == "archive":
                createdGames.remove(row[1])
                archivedGames.add(row[1])
            elif row[0] == "restore":
                archivedGames.remove(row[1])
                createdGames.add(row[1])
            elif row[0] == "delete":
                createdGames.discard(row[1])
                archivedGames.discard(row[1])
        csvfile.close()
        return list(createdGames), list(archivedGames)