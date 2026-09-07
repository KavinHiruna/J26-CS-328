import pandas as pd
import numpy as np
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# ==========================================
# 1. LOAD DATASET
# ==========================================

print("Loading dataset...")

file_path = "data/EdgeIIoT_train_80.csv"

df = pd.read_csv(file_path, low_memory=False)

print("Dataset shape:", df.shape)


# ==========================================
# 2. SELECT XAI-FRIENDLY FEATURES
# ==========================================

selected_features = [

    # TCP features
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.flags.ack",
    "tcp.len",

    # TCP connection behaviour
    "tcp.connection.syn",
    "tcp.connection.synack",
    "tcp.connection.fin",
    "tcp.connection.rst",

    # UDP features
    "udp.port",
    "udp.time_delta",

    # HTTP features
    "http.content_length",
    "http.request.method",

    # MQTT / IIoT features
    "mqtt.msgtype",
    "mqtt.len",
    "mqtt.hdrflags",
    "mqtt.topic_len",
    "mqtt.ver",

    # ARP features
    "arp.opcode",
    "arp.hw.size"
]


# ==========================================
# 3. CHECK AVAILABLE FEATURES
# ==========================================

available_features = []

for feature in selected_features:

    if feature in df.columns:
        available_features.append(feature)

    else:
        print(f"WARNING: Feature not found -> {feature}")


print("\nAvailable features:")
for feature in available_features:
    print(feature)


# ==========================================
# 4. CREATE NEW DATASET
# ==========================================

X = df[available_features].copy()

y = df["Attack_label"].copy()


# ==========================================
# 5. HANDLE MISSING VALUES
# ==========================================

print("\nHandling missing values...")

# Replace infinity values
X = X.replace([np.inf, -np.inf], np.nan)

# Fill numerical missing values
for column in X.columns:

    if X[column].dtype in ["float64", "int64"]:

        X[column] = X[column].fillna(X[column].median())

    else:

        X[column] = X[column].fillna("Unknown")


# ==========================================
# 6. ENCODE CATEGORICAL FEATURES
# ==========================================

print("\nEncoding categorical features...")

label_encoders = {}

for column in X.columns:

    if X[column].dtype == "object":

        encoder = LabelEncoder()

        X[column] = encoder.fit_transform(
            X[column].astype(str)
        )

        label_encoders[column] = encoder


# ==========================================
# 7. SAVE ENCODERS
# ==========================================

os.makedirs("models", exist_ok=True)

joblib.dump(
    label_encoders,
    "models/label_encoders.pkl"
)


# ==========================================
# 8. TRAIN / TEST SPLIT
# ==========================================

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


# ==========================================
# 9. SAVE PROCESSED DATA
# ==========================================

os.makedirs("data/processed", exist_ok=True)

X_train.to_csv(
    "data/processed/X_train.csv",
    index=False
)

X_test.to_csv(
    "data/processed/X_test.csv",
    index=False
)

y_train.to_csv(
    "data/processed/y_train.csv",
    index=False
)

y_test.to_csv(
    "data/processed/y_test.csv",
    index=False
)


# ==========================================
# 10. SAVE FEATURE NAMES
# ==========================================

joblib.dump(
    available_features,
    "models/feature_names.pkl"
)


print("\n=================================")
print("PREPROCESSING COMPLETED SUCCESSFULLY!")
print("=================================")

print("\nTraining samples:", X_train.shape)
print("Testing samples:", X_test.shape)

print("\nFeatures used:", len(available_features))

print("\nAttack distribution:")

print(y.value_counts(normalize=True) * 100)