# =========================================
# Phishing URL Detection - Flask Backend
# =========================================

from flask import Flask, request, render_template
import numpy as np
import pickle
from feature import FeatureExtraction

# -----------------------------------------
# Load Trained Model
# -----------------------------------------
with open("pickle/model.pkl", "rb") as file:
    model = pickle.load(file)

app = Flask(__name__)

# -----------------------------------------
# Home Route
# -----------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():

    safe_prob = None
    phishing_prob = None
    prediction = None
    url = None
    error = None

    if request.method == "POST":
        try:
            url = request.form.get("url", "").strip()

            # ---------------------------------
            # Ensure URL has scheme
            # ---------------------------------
            if not url.startswith(("http://", "https://")):
                url = "http://" + url

            # ---------------------------------
            # Feature Extraction
            # ---------------------------------
            extractor = FeatureExtraction(url)
            features = extractor.getFeaturesList()

            if len(features) != 30:
                raise ValueError("Feature extraction failed")

            X = np.array(features).reshape(1, -1)

            # ---------------------------------
            # Model Prediction
            # ---------------------------------
            prediction = int(model.predict(X)[0])

            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(X)[0]
                classes = model.classes_

                prob_dict = dict(zip(classes, probabilities))

                phishing_prob = round(prob_dict.get(-1, 0) * 100, 2)
                safe_prob = round(prob_dict.get(1, 0) * 100, 2)
            else:
                phishing_prob = 0
                safe_prob = 0

            # ---------------------------------
            # 🔒 Security Override (Short URL)
            # ---------------------------------
            # Feature index 2 = ShortURL
            if features[2] == -1:
                prediction = -1
                phishing_prob = 95.0
                safe_prob = 5.0

        except Exception as e:
            error = "Invalid URL or server error"

    return render_template(
        "index.html",
        safe_prob=safe_prob,
        phishing_prob=phishing_prob,
        prediction=prediction,
        url=url,
        error=error
    )


# -----------------------------------------
# Run Server
# -----------------------------------------
if __name__ == "__main__":
    app.run()