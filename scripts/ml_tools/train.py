import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import joblib

# Load the merged dataset
data = pd.read_csv("../data/combined_dataset.csv")

# Fill empty/missing text values
texts = data["text"].fillna("")
labels = data["label"]

# Convert text to numeric vectors
vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
X = vectorizer.fit_transform(texts)

# Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, labels, test_size=0.2, random_state=42
)

# Train model
model = LogisticRegression(max_iter=2000)
model.fit(X_train, y_train)

# Test accuracy
preds = model.predict(X_test)
acc = accuracy_score(y_test, preds)

print("✔ Training completed!")
print("✔ Accuracy:", acc)

# Save model and vectorizer
joblib.dump(model, "../data/phishing_model.pkl")
joblib.dump(vectorizer, "../data/vectorizer.pkl")

print("✔ Model saved as phishing_model.pkl")
print("✔ Vectorizer saved as vectorizer.pkl")
