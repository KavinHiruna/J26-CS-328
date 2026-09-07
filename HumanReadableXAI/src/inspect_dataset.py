import pandas as pd

# Load dataset
file_path = "data/EdgeIIoT_train_80.csv"

df = pd.read_csv(file_path, low_memory=False)

print("\n========== DATASET SHAPE ==========")
print(df.shape)

print("\n========== FIRST 5 ROWS ==========")
print(df.head())

print("\n========== COLUMN NAMES ==========")
for column in df.columns:
    print(column)

print("\n========== DATA TYPES ==========")
print(df.dtypes)

print("\n========== MISSING VALUES ==========")
print(df.isnull().sum())

print("\n========== ATTACK LABEL DISTRIBUTION ==========")
print(df["Attack_label"].value_counts())

print("\n========== UNIQUE VALUES ==========")
print(df.nunique().sort_values())