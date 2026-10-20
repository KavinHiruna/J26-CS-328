import csv

DATA_PATH = r"D:\Reserch\SOC_Component3\data\edgeiiot_ml.csv"

with open(DATA_PATH, "r", encoding="utf-8", errors="replace", newline="") as file:

    reader = csv.reader(file)

    header = next(reader)

    frame_index = header.index("frame.time")
    attack_type_index = header.index("Attack_type")
    label_index = header.index("Attack_label")

    print("frame.time column index:", frame_index)
    print("Attack_type column index:", attack_type_index)
    print("Attack_label column index:", label_index)

    print("\n========== FIRST 20 RAW ROWS ==========")

    for row_number, row in enumerate(reader, start=2):

        if row_number <= 21:

            print(
                f"\nRow {row_number}"
                f"\nframe.time = {repr(row[frame_index])}"
                f"\nAttack_label = {repr(row[label_index])}"
                f"\nAttack_type = {repr(row[attack_type_index])}"
            )