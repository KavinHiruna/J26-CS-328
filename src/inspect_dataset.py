import csv
from collections import Counter

DATA_PATH = r"D:\Reserch\SOC_Component3\data\edgeiiot_ml.csv"

print("Checking path:", DATA_PATH)
print("File exists:", __import__("os").path.exists(DATA_PATH))

print("\n========== READING DATASET ==========")

with open(DATA_PATH, "r", encoding="utf-8", errors="replace", newline="") as file:
    reader = csv.DictReader(file)

    columns = reader.fieldnames

    print("\n========== COLUMN NAMES ==========")
    print("Number of columns:", len(columns))

    for i, column in enumerate(columns, start=1):
        print(f"{i}. {column}")

    attack_types = Counter()
    attack_labels = Counter()
    row_count = 0

    print("\n========== FIRST 5 ROWS ==========")

    for row in reader:
        row_count += 1

        if row_count <= 5:
            print(row)

        if "Attack_type" in row:
            attack_types[row["Attack_type"]] += 1

        if "Attack_label" in row:
            attack_labels[row["Attack_label"]] += 1

print("\n========== DATASET SIZE ==========")
print("Number of rows:", row_count)
print("Number of columns:", len(columns))

print("\n========== ATTACK TYPES ==========")

for attack, count in attack_types.items():
    print(f"{attack}: {count}")

print("\n========== ATTACK LABELS ==========")

for label, count in attack_labels.items():
    print(f"{label}: {count}")

print("\n========== REQUIRED COMPONENT 3 FIELDS ==========")

required_columns = [
    "frame.time",
    "ip.src_host",
    "ip.dst_host",
    "Attack_label",
    "Attack_type"
]

for column in required_columns:
    if column in columns:
        print(f"{column}: FOUND")
    else:
        print(f"{column}: NOT FOUND")

print("\n========== INSPECTION COMPLETE ==========")