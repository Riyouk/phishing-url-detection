import pandas as pd
import pickle
from sklearn.ensemble import GradientBoostingClassifier

# Load dataset
data = pd.read_csv("dataset.csv")

print("Columns before cleaning:", data.columns)

# Remove Index column
if "Index" in data.columns:
    data = data.drop(columns=["Index"])

# Split features and target
X = data.drop(columns=["class"])
y = data["class"]

print("Feature count after cleaning:", X.shape[1])

# Train model
model = GradientBoostingClassifier()
model.fit(X, y)

# Save model
with open("pickle/model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained and saved successfully")