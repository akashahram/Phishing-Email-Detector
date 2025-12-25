import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, accuracy_score
import joblib
import re
import string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "data", "cleaned_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "..", "models")

os.makedirs(MODEL_DIR, exist_ok=True)

def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = text.translate(str.maketrans("", "", string.punctuation))
    text = re.sub(r"\d+", " NUM ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

print(f"Loading data from: {DATA_PATH}")

df = pd.read_csv(DATA_PATH)
df.dropna(subset=["text", "label"], inplace=True)

df["clean_text"] = df["text"].apply(clean_text)

X = df["clean_text"]
y = df["label"]

print("Vectorizing text with TF-IDF...")
vectorizer = TfidfVectorizer(
    max_features=3000,
    ngram_range=(1, 2),
    stop_words="english"
)

X_tfidf = vectorizer.fit_transform(X)

print("Train/test split...")
X_train, X_test, y_train, y_test = train_test_split(
    X_tfidf, y, test_size=0.2, random_state=42
)

print("Training LinearSVC + CalibratedClassifierCV...")
base_model = LinearSVC()
clf = CalibratedClassifierCV(estimator=base_model, cv=3)

clf.fit(X_train, y_train)

print("Evaluating model...")
y_pred = clf.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

acc = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {acc:.4f}")

model_path = os.path.join(MODEL_DIR, "phishing_model.pkl")
vectorizer_path = os.path.join(MODEL_DIR, "vectorizer.pkl")

joblib.dump(clf, model_path)
joblib.dump(vectorizer, vectorizer_path)

print(f"\nModel saved to: {model_path}")
print(f"Vectorizer saved to: {vectorizer_path}")
