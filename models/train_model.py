
from pathlib import Path

import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# 0 = Email binh thuong
# 1 = Email dang nghi ngo / co dau hieu lua dao

normal_emails = [
    "Cuoc hop nhom bat dau luc 9 gio sang mai",
    "Thay co da gui tai lieu bai giang",
    "Ban xem giup minh bao cao du an nhe",
    "Lich hoc ngay mai da duoc cap nhat",
    "Hen gap ban tai thu vien vao chieu nay",
    "Hoa don mua hang cua ban duoc dinh kem",
    "Cam on ban da tham gia buoi hop",
    "Bai tap tuan nay can nop truoc thu sau",
    "Your meeting starts at 10 AM tomorrow",
    "Please review the project report",
    "Your appointment is confirmed",
    "Here are the lecture notes",
    "The team meeting starts at noon",
    "Thank you for attending the meeting",
    "The class schedule has been updated",
    "Please find the meeting notes attached",
    "We will discuss the assignment tomorrow",
    "Your order confirmation is attached",
    "The project deadline is next Friday",
    "I have shared the presentation with you",
]

suspicious_emails = [
    "Tai khoan cua ban se bi khoa neu khong xac minh ngay",
    "Ban da trung thuong 50 trieu dong hay nhan thuong ngay",
    "Nhap mat khau de tranh bi khoa tai khoan",
    "Xac minh thong tin dang nhap ngay lap tuc",
    "Nhan qua mien phi bang cach cung cap thong tin ngan hang",
    "Tai khoan cua ban co dau hieu bat thuong hay dang nhap ngay",
    "Thong bao khan cap ban phai cap nhat mat khau ngay",
    "Nhan tien thuong ngay bang cach bam vao lien ket",
    "Cung cap ma OTP de xac nhan nhan qua",
    "Tai khoan se bi vo hieu hoa trong 24 gio neu khong xac minh",
    "Ban trung giai dac biet hay nop phi de nhan thuong",
    "Hay gui mat khau va ma xac minh de mo khoa tai khoan",
    "Urgent verify your account password immediately",
    "Congratulations you won a free prize click now",
    "Your account will be suspended verify now",
    "Claim your reward now by clicking this link",
    "Enter your password to avoid account closure",
    "Limited offer click now to get free money",
    "Confirm your login details immediately",
    "Send your one time password to receive your prize",
]

emails = normal_emails + suspicious_emails
labels = [0] * len(normal_emails) + [1] * len(suspicious_emails)

# Chia tap huan luyen va tap kiem tra
X_train, X_test, y_train, y_test = train_test_split(
    emails,
    labels,
    test_size=0.25,
    random_state=42,
    stratify=labels,
)

# Tao pipeline xu ly van ban va hoc may
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            strip_accents="unicode",
        ),
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
        ),
    ),
])

# Huan luyen mo hinh
model.fit(X_train, y_train)

# Danh gia tren tap kiem tra
predictions = model.predict(X_test)

print("KET QUA DANH GIA MO HINH")
print("So email:", len(emails))
print("So email huan luyen:", len(X_train))
print("So email kiem tra:", len(X_test))
print(f"Accuracy: {accuracy_score(y_test, predictions):.2%}")

print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Binh thuong", "Dang nghi ngo"],
        zero_division=0,
    )
)

# Luu mo hinh de Odoo su dung
output_path = Path(__file__).resolve().parent / "email_model.pkl"
joblib.dump(model, output_path)

print(f"Da luu mo hinh tai: {output_path}")

# Thu du doan voi email tieng Viet
test_email = (
    "Tai khoan cua ban se bi khoa trong 24 gio. "
    "Hay xac minh mat khau ngay de tranh mat quyen truy cap. "
    "Ban da trung thuong, hay cung cap thong tin ngan hang de nhan qua."
)

prediction = model.predict([test_email])[0]
probabilities = model.predict_proba([test_email])[0]
classes = list(model.named_steps["classifier"].classes_)
risk = probabilities[classes.index(1)] * 100

print("\nTHU DU DOAN EMAIL TIENG VIET")
print("Nhan du doan:", "Dang nghi ngo" if prediction == 1 else "Binh thuong")
print(f"Diem nghi ngo: {risk:.2f}%")
