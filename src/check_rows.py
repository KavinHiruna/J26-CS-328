import csv

DATA_PATH = r"D:\Reserch\SOC_Component3\data\edgeiiot_ml.csv"

with open(DATA_PATH, "r", encoding="utf-8", errors="replace", newline="") as file:

    reader = csv.reader(file)

    header = next(reader)
    expected_columns = len(header)

    print("Expected columns:", expected_columns)

    normal_rows = 0
    short_rows = 0
    long_rows = 0

    print("\n========== ROW STRUCTURE CHECK ==========")

    for row_number, row in enumerate(reader, start=2):

        column_count = len(row)

        if column_count == expected_columns:
            normal_rows += 1

        elif column_count < expected_columns:
            short_rows += 1

            if short_rows <= 10:
                print(
                    f"SHORT ROW {row_number}: "
                    f"{column_count} columns"
                )

        else:
            long_rows += 1

            if long_rows <= 10:
                print(
                    f"LONG ROW {row_number}: "
                    f"{column_count} columns"
                )

    print("\n========== RESULT ==========")
    print("Normal rows:", normal_rows)
    print("Short rows:", short_rows)
    print("Long rows:", long_rows)
    print("Total rows:", normal_rows + short_rows + long_rows)