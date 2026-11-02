
from pathlib import Path
import joblib

# Duong dan den mo hinh da huan luyen
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "email_model.pkl"

# Nap mo hinh
model = joblib.load(MODEL_PATH)

print("MO HINH AI DA DUOC NAP THANH CONG")

# Thu voi mot so email moi
test_emails = [
    "The team meeting starts at 10 AM tomorrow",
    "Congratulations! Click now to claim your free prize",
    "Urgent! Verify your account password immediately",
]

# Du doan nhan email
predictions = model.predict(test_emails)
probabilities = model.predict_proba(test_emails)
classes = model.named_steps["classifier"].classes_

for email, prediction, probability in zip(
    test_emails, predictions, probabilities
):
    print("\nEmail:", email)
    print("Du doan:", prediction)

    for label, score in zip(classes, probability):
        print(f"  {label}: {score * 100:.2f}%")
