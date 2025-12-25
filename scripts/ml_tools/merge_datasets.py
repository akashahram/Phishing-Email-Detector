import os
import pandas as pd

data_folder = "../data/"
files = [f for f in os.listdir(data_folder) if f.endswith(".csv")]

all_rows = []

for file in files:
    print("Reading:", file)
    df = pd.read_csv(data_folder + file, encoding="latin-1")


    # Try to detect a text column
    possible_text_cols = ["text", "email", "message", "body", "content"]
    text_col = None

    for col in df.columns:
        if col.lower() in possible_text_cols:
            text_col = col
            break

    # If no specific text column found, assume first column is text
    if text_col is None:
        text_col = df.columns[0]

    # Try to detect label column
    possible_label_cols = ["label", "phishing", "spam", "target"]
    label_col = None

    for col in df.columns:
        if col.lower() in possible_label_cols:
            label_col = col
            break

    # If no label found, assume phishing email (label 1)
    if label_col is None:
        df["label"] = 1
        label_col = "label"

    temp = df[[text_col, label_col]].copy()
    temp.columns = ["text", "label"]
    all_rows.append(temp)

# Merge everything
final_df = pd.concat(all_rows, ignore_index=True)

# Save
final_df.to_csv("../data/combined_dataset.csv", index=False)

print("✔ All files merged into combined_dataset.csv")
print("✔ Total rows:", len(final_df))
