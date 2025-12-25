# prepare_dataset.py
import os
import pandas as pd
from sklearn.utils import resample

ROOT = os.path.join(os.path.dirname(__file__), "..")
DATA_IN = os.path.join(ROOT, "data", "combined_dataset.csv")
DATA_OUT = os.path.join(ROOT, "data", "cleaned_dataset.csv")

print("Loading:", DATA_IN)
df = pd.read_csv(DATA_IN, encoding="utf-8", low_memory=False)

# Ensure column names (accept 'text' or first column)
if "text" not in df.columns:
    df.columns = ["text", "label"] + list(df.columns[2:])

# Drop nulls and empties
df["text"] = df["text"].astype(str).str.strip()
df = df[df["text"].str.len() > 5].copy()
df = df.dropna(subset=["label"])

# Normalize labels to 0/1 if needed
df["label"] = df["label"].astype(int)

# Remove duplicates
df = df.drop_duplicates(subset=["text"])

# Check class balance
count0 = (df["label"]==0).sum()
count1 = (df["label"]==1).sum()
print("Class counts before:", count0, count1)

# If imbalanced, downsample majority class to match minority (safe/simple)
if abs(count0 - count1) > 0:
    if count0 > count1:
        df_major = df[df["label"]==0]
        df_minor = df[df["label"]==1]
    else:
        df_major = df[df["label"]==1]
        df_minor = df[df["label"]==0]

    df_major_down = resample(df_major, replace=False, n_samples=len(df_minor), random_state=42)
    df = pd.concat([df_major_down, df_minor]).sample(frac=1, random_state=42)

count0 = (df["label"]==0).sum()
count1 = (df["label"]==1).sum()
print("Class counts after:", count0, count1)

# Save cleaned dataset
df.to_csv(DATA_OUT, index=False)
print("Saved cleaned dataset to:", DATA_OUT)
