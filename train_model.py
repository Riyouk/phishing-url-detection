import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier

# load dataset
data = pd.read_csv("phishing.csv")

print("Columns:", data.columns)

# last column is the label
X = data.iloc[:, :-1]
y = data.iloc[:, -1]

# split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# train model
model = GradientBoostingClassifier()
model.fit(X_train, y_train)

# save model
with open("pickle/model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained and saved successfully")