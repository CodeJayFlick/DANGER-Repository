import csv

input_csv_filename = "aggregate_data\\about_samples.csv"
output_csv_filename = "about_samples_clean.csv"

input_csv_file = open(input_csv_filename, 'r')
csv_reader = csv.reader(input_csv_file)

output_csv_file = open(output_csv_filename, 'w', newline='')
csv_writer = csv.writer(output_csv_file)

for row in csv_reader:
    if row == []:
        continue
    csv_writer.writerow(row)