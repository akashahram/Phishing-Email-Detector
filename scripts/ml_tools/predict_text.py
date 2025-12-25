import joblib

# Load model and vectorizer
model = joblib.load("../data/phishing_model.pkl")
vectorizer = joblib.load("../data/vectorizer.pkl")

print("Phishing Email Detector")
print("Type 'exit' to quit")

while True:
    email = input("\nPaste email text here: ")
    if email.lower() == "exit":
        break
    X = vectorizer.transform([email])
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0][pred]

    if pred == 1:
        print(f"⚠️ Phishing detected! Probability: {prob*100:.2f}%")
    else:
        print(f"✅ Legitimate email. Probability: {prob*100:.2f}%")
