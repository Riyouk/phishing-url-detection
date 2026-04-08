import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier

# Load dataset
data = pd.read_csv("phishing.csv")

# 🔥 IMPORTANT FIX
if "Index" in data.columns:
    data = data.drop("Index", axis=1)

# Split data
X = data.drop("class", axis=1)
y = data["class"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = GradientBoostingClassifier()
model.fit(X_train, y_train)

# Save model
with open("pickle/model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model retrained successfully with correct features")