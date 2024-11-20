import csv
from io import IOErrors

class CsvAdjacencyListGraphExporter:
    CVS_DELIMITER = ','

    def export_graph(self, graph, file):
        try:
            with open(file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                for vertex in graph.vertices():
                    row = [vertex.id]
                    for edge in vertex.edges():
                        row.append(edge.target_vertex().id)
                    writer.writerow(row)
        except Exception as e:
            raise IOErrors(str(e))

    def get_file_extension(self):
        return 'csv'

    def get_name(self):
        return 'CSV:Adjacency List'

    def get_description(self):
        return 'JGraphT library export of a graph to a adjacency list CSV file'
