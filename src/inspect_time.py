import csv
from collections import Counter

DATA_PATH = r"D:\Reserch\SOC_Component3\data\edgeiiot_ml.csv"

print("\n========== TIME FIELD INSPECTION ==========")

with open(DATA_PATH, "r", encoding="utf-8", errors="replace", newline="") as file:

    reader = csv.DictReader(file)

    times = []
    attack_times = []

    for row in reader:
        time_value = row["frame.time"]
        attack_type = row["Attack_type"]

        times.append(time_value)

        if attack_type != "Normal":
            attack_times.append(time_value)

print("\nTotal time values:", len(times))
print("Attack time values:", len(attack_times))

print("\n========== FIRST 30 TIME VALUES ==========")

for value in times[:30]:
    print(repr(value))

print("\n========== UNIQUE TIME VALUES ==========")

unique_times = set(times)

print("Number of unique time values:", len(unique_times))

print("\nFirst 30 unique values:")

for value in list(unique_times)[:30]:
    print(repr(value))

print("\n========== TIME FREQUENCY ==========")

time_counts = Counter(times)

for time_value, count in time_counts.most_common(20):
    print(f"{repr(time_value)} : {count}")

print("\n========== INSPECTION COMPLETE ==========")