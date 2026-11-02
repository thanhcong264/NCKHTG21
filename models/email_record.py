
import logging
from pathlib import Path
from html import escape

import joblib

from odoo import models, fields
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class EmailPhishingCheck(models.Model):
    _name = "email.phishing.check"
    _description = "Email Phishing Detection"
    _order = "create_date desc"

    # ── CHONG TRUNG LAP: chi bat buoc voi email tu IMAP ──────────────────
    # UNIQUE(message_id) tuong thich voi moi cai dat PostgreSQL,
    # khong can extension btree_gist.
    # PostgreSQL (SQL standard) cho phep nhieu gia tri NULL trong cot UNIQUE,
    # nen record nhap tay (message_id=False/NULL) khong bi anh huong.
    _sql_constraints = [
        (
            "unique_message_id",
            "UNIQUE(message_id)",
            "Email với Message-ID này đã tồn tại trong hệ thống.",
        ),
    ]

    # THONG TIN EMAIL
    name = fields.Char(
        string="Tiêu đề email",
        required=True,
    )

    sender = fields.Char(
        string="Email người gửi",
        required=True,
    )

    recipient_email = fields.Char(
        string="Email người nhận",
        required=True,
    )

    email_body = fields.Text(
        string="Nội dung email",
        required=True,
    )

    # NGUON EMAIL VA THONG TIN IMAP
    message_id = fields.Char(
        string="Message-ID",
        index=True,
        readonly=True,
        copy=False,
        help=(
            "Định danh duy nhất của email theo chuẩn RFC 2822. "
            "Tự động điền khi email được lấy qua IMAP. "
            "Dùng để chống lưu trùng lặp."
        ),
    )

    received_date = fields.Datetime(
        string="Ngày nhận",
        readonly=True,
        help="Thời điểm email được gửi đến hộp thư, lấy từ header Date của IMAP.",
    )

    source = fields.Selection(
        [
            ("manual", "Nhập tay"),
            ("imap", "IMAP tự động"),
        ],
        string="Nguồn",
        default="manual",
        required=True,
        readonly=True,
        help=(
            "'Nhập tay': người dùng tự tạo qua giao diện Odoo. "
            "'IMAP tự động': hệ thống tự lấy từ hộp thư qua giao thức IMAP."
        ),
    )

    # KET QUA PHAN TICH AI
    prediction = fields.Selection(
        [
            ("pending", "Chưa phân tích"),
            ("safe", "AN TOÀN"),
            ("warning", "CẢNH BÁO"),
            ("phishing", "NGHI NGỜ LỪA ĐẢO"),
        ],
        string="Kết quả AI",
        default="pending",
        required=True,
        readonly=True,
    )

    risk_score = fields.Float(
        string="Điểm rủi ro (%)",
        default=0.0,
        readonly=True,
    )

    # PHAN TICH EMAIL BANG MACHINE LEARNING
    def action_analyze_email(self):
        model_path = (
            Path(__file__).resolve().parent / "email_model.pkl"
        )

        if not model_path.exists():
            raise UserError(
                "Không tìm thấy file email_model.pkl.\n"
                "Hãy kiểm tra thư mục models của module."
            )

        try:
            ai_model = joblib.load(model_path)
        except Exception as error:
            raise UserError(
                f"Không thể tải mô hình AI: {error}"
            ) from error

        for record in self:
            if not record.email_body or not record.email_body.strip():
                raise UserError(
                    "Vui lòng nhập nội dung email trước khi phân tích."
                )

            try:
                result = ai_model.predict(
                    [record.email_body]
                )[0]

                probabilities = ai_model.predict_proba(
                    [record.email_body]
                )[0]

                classes = list(
                    ai_model.named_steps["classifier"].classes_
                )

                if 1 not in classes:
                    raise UserError(
                        "Mô hình không có nhãn 1 cho email đáng ngờ. "
                        "Hãy kiểm tra lại dữ liệu huấn luyện."
                    )

                suspicious_index = classes.index(1)

                risk = float(
                    probabilities[suspicious_index]
                ) * 100

                # NGUONG PHAN LOAI CHO BAN DEMO
                if risk >= 70:
                    prediction = "phishing"
                elif risk >= 40:
                    prediction = "warning"
                else:
                    prediction = "safe"

                record.write({
                    "prediction": prediction,
                    "risk_score": risk,
                })

            except UserError:
                raise
            except Exception as error:
                raise UserError(
                    f"Lỗi khi phân tích email: {error}"
                ) from error

        return True

    # GUI EMAIL CANH BAO KEM NOI DUNG EMAIL GOC
    def action_send_warning_email(self):
        for record in self:
            if not record.recipient_email:
                raise UserError(
                    "Vui lòng nhập email người nhận."
                )

            if record.prediction == "pending":
                raise UserError(
                    "Vui lòng phân tích email trước khi gửi cảnh báo."
                )

            if not record.email_body or not record.email_body.strip():
                raise UserError(
                    "Nội dung email gốc đang trống. "
                    "Vui lòng nhập nội dung trước khi gửi."
                )

            # NHAN HIEN THI
            result_labels = {
                "safe": "AN TOÀN",
                "warning": "CẢNH BÁO",
                "phishing": "NGHI NGỜ LỪA ĐẢO",
            }

            result = result_labels.get(
                record.prediction,
                "CHƯA XÁC ĐỊNH",
            )

            # KHUYEN NGHI THEO KET QUA
            advice_map = {
                "phishing": (
                    "Không nhấn vào liên kết, không mở tệp đính kèm "
                    "đáng ngờ và không cung cấp mật khẩu hoặc mã OTP."
                ),
                "warning": (
                    "Hãy kiểm tra kỹ người gửi và nội dung email "
                    "trước khi thực hiện yêu cầu."
                ),
                "safe": (
                    "Mô hình chưa phát hiện đủ dấu hiệu đáng ngờ. "
                    "Bạn vẫn nên kiểm tra liên kết và tệp đính kèm."
                ),
            }

            advice = advice_map.get(
                record.prediction,
                "Hãy kiểm tra email cẩn thận.",
            )

            # ESCAPE DU LIEU TRUOC KHI CHEN VAO HTML
            safe_name = escape(record.name or "")
            safe_sender = escape(record.sender or "")
            safe_result = escape(result)
            safe_advice = escape(advice)

            safe_risk = f"{record.risk_score:.2f}"

            # Bao toan xuong dong, dong thoi ngan HTML goc
            # trong email canh bao lam vo giao dien.
            safe_original_body = escape(
                record.email_body or ""
            ).replace("\r\n", "\n").replace("\r", "\n")

            safe_original_body = safe_original_body.replace(
                "\n", "<br/>"
            )

            # MAU SAC THEO KET QUA
            if record.prediction == "phishing":
                color = "#dc2626"
                background = "#fef2f2"
            elif record.prediction == "warning":
                color = "#ca8a04"
                background = "#fffbeb"
            else:
                color = "#15803d"
                background = "#f0fdf4"

            # TAO NOI DUNG HTML GUI DEN GMAIL
            body_html = f"""
            <div style="
                font-family: Arial, Helvetica, sans-serif;
                font-size: 15px;
                line-height: 1.7;
                color: #222222;
                max-width: 720px;
                margin: 0 auto;
            ">

                <div style="
                    background-color: {color};
                    color: #ffffff;
                    padding: 20px;
                    border-radius: 8px 8px 0 0;
                ">
                    <h2 style="margin: 0;">
                        CẢNH BÁO EMAIL
                    </h2>
                    <p style="margin-bottom: 0;">
                        Hệ thống Email Security đã hoàn tất phân tích.
                    </p>
                </div>

                <div style="
                    border: 1px solid #dddddd;
                    padding: 20px;
                ">

                    <div style="
                        background-color: {background};
                        border-left: 5px solid {color};
                        padding: 12px 16px;
                        margin-bottom: 20px;
                    ">
                        <h3 style="margin-top: 0; color: {color};">
                            {safe_result}
                        </h3>

                        <p style="margin-bottom: 0;">
                            <b>Điểm nghi ngờ:</b> {safe_risk}%
                        </p>
                    </div>

                    <h3>THÔNG TIN EMAIL</h3>

                    <p>
                        <b>Tiêu đề email:</b><br/>
                        {safe_name}
                    </p>

                    <p>
                        <b>Người gửi gốc:</b><br/>
                        {safe_sender}
                    </p>

                    <hr style="border: 0; border-top: 1px solid #dddddd;"/>

                    <h3>NỘI DUNG EMAIL GỐC</h3>

                    <p style="color: #555555;">
                        Đây là nội dung email được đưa vào hệ thống
                        để mô hình AI phân tích:
                    </p>

                    <div style="
                        background-color: #f5f5f5;
                        border: 1px solid #e5e5e5;
                        border-left: 4px solid {color};
                        border-radius: 4px;
                        padding: 16px;
                        overflow-wrap: anywhere;
                        word-wrap: break-word;
                    ">
                        {safe_original_body}
                    </div>

                    <hr style="border: 0; border-top: 1px solid #dddddd;"/>

                    <h3> KHUYẾN NGHỊ AN TOÀN </h3>

                    <p>{safe_advice}</p>

                    <p>
                        Nếu email yêu cầu cung cấp mật khẩu, mã OTP,
                        thông tin ngân hàng hoặc truy cập đường dẫn lạ,
                        hãy xác minh thông tin qua kênh chính thức.
                    </p>

                    <hr style="border: 0; border-top: 1px solid #dddddd;"/>

                    <p style="
                        color: #777777;
                        font-size: 12px;
                    ">
                        Đây là kết quả hỗ trợ từ mô hình AI thử nghiệm,
                        không phải kết luận bảo đảm tuyệt đối.
                    </p>

                    <p style="
                        color: #777777;
                        font-size: 12px;
                    ">
                        Email Security - Hệ thống phân tích email.
                    </p>

                </div>
            </div>
            """

            # TIM MAY CHU GUI EMAIL DANG HOAT DONG
            mail_server = self.env["ir.mail_server"].sudo().search(
                [("active", "=", True)],
                order="sequence, id",
                limit=1,
            )

            if not mail_server:
                raise UserError(
                    "Không có máy chủ thư đi đang hoạt động. "
                    "Hãy kiểm tra Cài đặt → Kỹ thuật → Email "
                    "→ Máy chủ thư đi."
                )

            # UU TIEN DIA CHI TAI KHOAN SMTP
            email_from = (
                mail_server.smtp_user
                or self.env.user.email
                or self.env.company.email
            )

            if not email_from:
                raise UserError(
                    "Không tìm thấy địa chỉ người gửi. "
                    "Hãy cấu hình email người dùng, công ty "
                    "hoặc tài khoản SMTP."
                )

            try:
                mail = self.env["mail.mail"].sudo().create({
                    "subject": (
                        f"[Email Security] {result}: {record.name}"
                    ),
                    "email_to": record.recipient_email.strip(),
                    "email_from": email_from,
                    "body_html": body_html,
                    "mail_server_id": mail_server.id,
                })

                # GUI EMAIL QUA SMTP
                mail.send()
                mail.invalidate_recordset()

                if mail.state == "exception":
                    detail = (
                        getattr(mail, "failure_reason", False)
                        or "Odoo chưa cung cấp chi tiết lỗi."
                    )

                    raise UserError(
                        "Gửi email thất bại.\n"
                        f"Máy chủ: {mail_server.name}\n"
                        f"Người gửi: {email_from}\n"
                        f"Chi tiết: {detail}"
                    )

            except UserError:
                raise
            except Exception as error:
                raise UserError(
                    "Không gửi được email.\n"
                    f"Máy chủ: {mail_server.name}\n"
                    f"Chi tiết: {error}"
                ) from error

        return True
