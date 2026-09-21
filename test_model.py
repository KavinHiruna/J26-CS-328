from model_pipeline import load_data
from sklearn.metrics import accuracy_score
import joblib

df, X, y = load_data()
bundle = joblib.load("models/random_forest_ids.joblib")
model = bundle["model"]

pred = model.predict(X)
print("Prototype accuracy on complete demo dataset:", accuracy_score(y, pred))
