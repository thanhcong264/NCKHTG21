from datetime import timezone
import email
import email.policy
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
from html.parser import HTMLParser
import imaplib
import logging
import ssl

from odoo import models, fields, api
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class HTMLTextExtractor(HTMLParser):
    """Trích xuất text thuần từ nội dung HTML."""

    def __init__(self):
        super().__init__()
        self.text_parts = []

    def handle_data(self, data):
        cleaned = data.strip()
        if cleaned:
            self.text_parts.append(cleaned)

    def get_text(self):
        return " ".join(self.text_parts)


class EmailImapConfig(models.Model):
    _name = "email.imap.config"
    _description = "Cấu hình IMAP Gmail"
    _order = "id desc"

    name = fields.Char(
        string="Tên cấu hình",
        required=True,
        default="Gmail IMAP",
    )

    imap_host = fields.Char(
        string="Máy chủ IMAP",
        required=True,
        default="imap.gmail.com",
        help="Địa chỉ máy chủ IMAP (mặc định: imap.gmail.com)",
    )

    imap_port = fields.Integer(
        string="Cổng IMAP",
        required=True,
        default=993,
        help="Cổng kết nối SSL IMAP (mặc định: 993)",
    )

    imap_user = fields.Char(
        string="Tài khoản Gmail",
        required=True,
        help="Địa chỉ email Gmail (ví dụ: yourname@gmail.com)",
    )

    imap_password = fields.Char(
        string="Mật khẩu ứng dụng (App Password)",
        required=True,
        password=True,
        groups="base.group_system",
        help=(
            "Mật khẩu ứng dụng 16 ký tự được tạo từ Google Account "
            "(Security -> 2-Step Verification -> App passwords). "
            "Lưu ý: Không dùng mật khẩu đăng nhập tài khoản chính."
        ),
    )

    use_ssl = fields.Boolean(
        string="Sử dụng SSL",
        default=True,
        readonly=True,
        help="Gmail bắt buộc sử dụng SSL qua cổng 993.",
    )

    folder = fields.Char(
        string="Thư mục lấy thư",
        default="INBOX",
        required=True,
        help="Thư mục hộp thư trên máy chủ IMAP (mặc định: INBOX)",
    )

    filter_type = fields.Selection(
        [
            ("unseen", "Chỉ email chưa đọc (UNSEEN)"),
            ("all", "Tất cả email (ALL)"),
        ],
        string="Bộ lọc email",
        default="unseen",
        required=True,
        help="Lọc chỉ lấy email chưa đọc hoặc lấy tất cả (sẽ lọc trùng bằng Message-ID).",
    )

    fetch_limit = fields.Integer(
        string="Số email tối đa mỗi lần",
        default=20,
        required=True,
        help="Giới hạn số lượng email tải về trong mỗi đợt lấy (tối đa khuyến nghị: 20-50).",
    )

    auto_analyze = fields.Boolean(
        string="Tự động phân tích AI",
        default=True,
        help="Tự động chạy mô hình phân tích phishing sau khi lưu email vào hệ thống.",
    )

    active = fields.Boolean(
        string="Đang hoạt động",
        default=True,
    )

    last_fetch_date = fields.Datetime(
        string="Lần lấy gần nhất",
        readonly=True,
    )

    last_fetch_status = fields.Text(
        string="Trạng thái lần lấy gần nhất",
        readonly=True,
    )

    fetched_count_total = fields.Integer(
        string="Tổng số email đã lấy",
        readonly=True,
        default=0,
    )

    # ── KẾT NỐI IMAP NỘI BỘ ──────────────────────────────────────────────

    def _get_imap_connection(self):
        """Khởi tạo kết nối IMAP SSL an toàn và đăng nhập."""
        self.ensure_one()
        if not self.imap_user or not self.imap_password:
            raise UserError("Vui lòng nhập đầy đủ tài khoản và mật khẩu ứng dụng Gmail.")

        try:
            # Tạo SSL context an toàn
            ssl_context = ssl.create_default_context()
            connection = imaplib.IMAP4_SSL(
                host=self.imap_host,
                port=self.imap_port,
                ssl_context=ssl_context,
                timeout=30,
            )
            # Đăng nhập bằng tài khoản và App Password
            connection.login(self.imap_user.strip(), self.imap_password.strip())
            return connection
        except imaplib.IMAP4.error as err:
            _logger.error(
                "Lỗi xác thực IMAP cho người dùng %s: %s",
                self.imap_user,
                str(err),
            )
            raise UserError(
                f"Đăng nhập IMAP thất bại: {err}\n"
                "Gợi ý: Kiểm tra lại địa chỉ email và Mật khẩu ứng dụng (16 ký tự). "
                "Đảm bảo đã bật xác minh 2 bước trên Google."
            ) from err
        except Exception as err:
            _logger.exception(
                "Lỗi kết nối IMAP đến %s:%s",
                self.imap_host,
                self.imap_port,
            )
            raise UserError(
                f"Không thể kết nối đến máy chủ IMAP ({self.imap_host}:{self.imap_port}): {err}"
            ) from err

    # ── NÚT KIỂM TRA KẾT NỐI ─────────────────────────────────────────────

    def action_test_connection(self):
        """Kiểm tra kết nối IMAP và thông báo kết quả."""
        self.ensure_one()
        connection = None
        try:
            connection = self._get_imap_connection()
            # readonly=True: Đảm bảo không thay đổi bất kỳ trạng thái nào trên Gmail
            status, data = connection.select(self.folder or "INBOX", readonly=True)
            if status != "OK":
                raise UserError(f"Không thể mở thư mục '{self.folder}': {data}")

            # Đếm số lượng email hiện có trong hộp thư
            total_messages = 0
            if data and data[0]:
                try:
                    total_messages = int(data[0].decode())
                except Exception:
                    pass

            msg = (
                f"Kết nối IMAP Gmail thành công!\n"
                f"- Thư mục: {self.folder}\n"
                f"- Tổng số email trong hộp thư: {total_messages}"
            )
            return {
                "type": "ir.actions.client",
                "tag": "display_notification",
                "params": {
                    "title": "Kiểm tra kết nối",
                    "message": msg,
                    "type": "success",
                    "sticky": False,
                },
            }
        finally:
            if connection:
                try:
                    connection.close()
                except Exception:
                    pass
                try:
                    connection.logout()
                except Exception:
                    pass

    # ── TRÍCH XUẤT BODY VÀ THÔNG TIN TỪ MIME MESSAGE ────────────────────

    def _extract_body_from_message(self, message):
        """Trích xuất nội dung văn bản từ email (ưu tiên text/plain, fallback HTML)."""
        body_text = ""

        try:
            # 1. Thử lấy text/plain qua email.policy.default
            plain_body = message.get_body(preferencelist=("plain",))
            if plain_body:
                body_text = plain_body.get_content()
        except Exception:
            pass

        # 2. Nếu chưa có plain text, thử lấy text/html rồi strip tags
        if not body_text or not body_text.strip():
            try:
                html_body = message.get_body(preferencelist=("html",))
                if html_body:
                    raw_html = html_body.get_content()
                    parser = HTMLTextExtractor()
                    parser.feed(raw_html)
                    body_text = parser.get_text()
            except Exception:
                pass

        # 3. Fallback cho legacy mime messages (duyệt parts)
        if not body_text or not body_text.strip():
            try:
                if message.is_multipart():
                    for part in message.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition", ""))
                        if "attachment" in content_disposition:
                            continue
                        if content_type == "text/plain":
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or "utf-8"
                                body_text = payload.decode(charset, errors="replace")
                                break
                        elif content_type == "text/html" and not body_text:
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or "utf-8"
                                raw_html = payload.decode(charset, errors="replace")
                                parser = HTMLTextExtractor()
                                parser.feed(raw_html)
                                body_text = parser.get_text()
                else:
                    payload = message.get_payload(decode=True)
                    if payload:
                        charset = message.get_content_charset() or "utf-8"
                        body_text = payload.decode(charset, errors="replace")
            except Exception as err:
                _logger.warning("Lỗi trích xuất payload email: %s", err)

        return body_text.strip() if body_text else "(Không có nội dung)"

    def _parse_email_date(self, date_header):
        """Chuyển đổi header Date RFC 2822 thành naive UTC datetime cho Odoo."""
        if not date_header:
            return fields.Datetime.now()
        try:
            dt = parsedate_to_datetime(date_header)
            if dt is not None:
                # Nếu có timezone info, chuyển sang UTC rồi bỏ tzinfo
                if dt.tzinfo is not None:
                    utc_dt = dt.astimezone(timezone.utc)
                    return utc_dt.replace(tzinfo=None)
                return dt
        except Exception:
            pass
        return fields.Datetime.now()

    # ── LOGIC LẤY EMAIL TỪ GMAIL ────────────────────────────────────────

    def _fetch_emails(self):
        """Hàm thực thi logic lấy email từ Gmail qua IMAP."""
        self.ensure_one()
        connection = None
        new_records = self.env["email.phishing.check"]
        skipped_count = 0
        error_count = 0

        try:
            connection = self._get_imap_connection()
            # readonly=True: ĐẢM BẢO KHÔNG XÓA HOẶC LÀM MẤT EMAIL TRÊN GMAIL
            status, _ = connection.select(self.folder or "INBOX", readonly=True)
            if status != "OK":
                raise UserError(f"Không thể mở thư mục '{self.folder}'.")

            # Tiêu chí tìm kiếm
            search_criterion = "UNSEEN" if self.filter_type == "unseen" else "ALL"
            status, search_data = connection.uid("search", None, search_criterion)

            if status != "OK" or not search_data or not search_data[0]:
                status_msg = f"Không có email nào thỏa mãn tiêu chí '{search_criterion}'."
                self.write({
                    "last_fetch_date": fields.Datetime.now(),
                    "last_fetch_status": status_msg,
                })
                return new_records, 0, 0

            # Danh sách UID
            all_uids = search_data[0].split()
            # Lấy các email mới nhất theo giới hạn fetch_limit
            limit = max(1, self.fetch_limit or 20)
            uids_to_process = all_uids[-limit:]

            phishing_model = self.env["email.phishing.check"]

            for uid in uids_to_process:
                try:
                    with self.env.cr.savepoint():
                        # BODY.PEEK[] kết hợp select(readonly=True) đảm bảo tuyệt đối không đánh dấu \Seen (đã đọc) trên Gmail
                        res_status, msg_parts = connection.uid("fetch", uid, "(BODY.PEEK[])")
                        if res_status != "OK" or not msg_parts or not msg_parts[0]:
                            error_count += 1
                            continue

                        raw_email_bytes = None
                        for part in msg_parts:
                            if isinstance(part, tuple) and len(part) > 1:
                                raw_email_bytes = part[1]
                                break

                        if not raw_email_bytes:
                            error_count += 1
                            continue

                        # Parse MIME email bằng chính sách chuẩn (tự giải mã header UTF-8)
                        email_msg = email.message_from_bytes(
                            raw_email_bytes,
                            policy=email.policy.default,
                        )

                        # 1. Trích xuất Message-ID
                        raw_msg_id = email_msg.get("Message-ID", "")
                        message_id = raw_msg_id.strip() if raw_msg_id else False

                        # 2. Trích xuất thông tin người gửi, nhận, tiêu đề
                        subject = str(email_msg.get("Subject", "")).strip() or "(Không có tiêu đề)"
                        from_header = str(email_msg.get("From", "")).strip()
                        to_header = str(email_msg.get("To", "")).strip()

                        _, sender_email = parseaddr(from_header)
                        sender_final = sender_email or from_header or "unknown@domain.com"

                        _, to_email = parseaddr(to_header)
                        recipient_final = to_email or to_header or self.imap_user

                        date_header = email_msg.get("Date")
                        received_date = self._parse_email_date(date_header)

                        # 3. Chống trùng email:
                        # Nếu email thiếu RFC 2822 Message-ID, tạo định danh dự phòng dựa trên SHA-256
                        # của toàn bộ raw_email_bytes (dữ liệu email thô bất biến trên máy chủ IMAP).
                        # Cách này đảm bảo:
                        # - Lần lấy sau không bị tính lại thành email mới (không sinh trùng).
                        # - Hai email khác nhau (kể cả cùng sender, tiêu đề và ngày) vẫn có hash khác nhau.
                        if not message_id:
                            content_hash = hashlib.sha256(raw_email_bytes).hexdigest()
                            message_id = f"<fallback_{content_hash}@local>"

                        # Kiểm tra xem Message-ID đã có trong CSDL chưa
                        existing = phishing_model.search([
                            ("message_id", "=", message_id)
                        ], limit=1)

                        if existing:
                            skipped_count += 1
                            continue

                        # 4. Trích xuất nội dung email
                        body_content = self._extract_body_from_message(email_msg)

                        # 5. Tạo bản ghi email.phishing.check
                        vals = {
                            "name": subject,
                            "sender": sender_final,
                            "recipient_email": recipient_final,
                            "email_body": body_content,
                            "message_id": message_id,
                            "received_date": received_date,
                            "source": "imap",
                        }

                        record = phishing_model.create(vals)
                        new_records |= record

                        # 6. Tự động phân tích AI nếu được bật (bắt lỗi riêng để không mất bản ghi)
                        if self.auto_analyze:
                            try:
                                record.action_analyze_email()
                            except Exception as ai_err:
                                _logger.warning(
                                    "Lỗi khi tự động phân tích AI cho email ID %s: %s",
                                    record.id,
                                    ai_err,
                                )

                except Exception as loop_err:
                    _logger.exception("Lỗi khi xử lý email UID %s: %s", uid, loop_err)
                    error_count += 1

            # Cập nhật trạng thái cấu hình
            success_count = len(new_records)
            status_summary = (
                f"Đã xử lý {len(uids_to_process)} email: "
                f"Thêm mới: {success_count}, Trùng lặp bỏ qua: {skipped_count}, Lỗi: {error_count}."
            )

            self.write({
                "last_fetch_date": fields.Datetime.now(),
                "last_fetch_status": status_summary,
                "fetched_count_total": self.fetched_count_total + success_count,
            })

            return new_records, skipped_count, error_count

        finally:
            if connection:
                try:
                    connection.close()
                except Exception:
                    pass
                try:
                    connection.logout()
                except Exception:
                    pass

    # ── NÚT LẤY EMAIL THỦ CÔNG ──────────────────────────────────────────

    def action_fetch_emails(self):
        """Hành động nút thủ công: Lấy email và hiển thị thông báo kết quả."""
        total_created = 0
        total_skipped = 0
        total_errors = 0

        for config in self:
            created_records, skipped, errors = config._fetch_emails()
            total_created += len(created_records)
            total_skipped += skipped
            total_errors += errors

        notification_msg = (
            f"Kết quả lấy email từ Gmail:\n"
            f"- Đã lưu mới thành công: {total_created} email\n"
            f"- Email trùng lặp (bỏ qua): {total_skipped}\n"
        )
        if total_errors > 0:
            notification_msg += f"- Email lỗi: {total_errors}\n"

        if self.auto_analyze and total_created > 0:
            notification_msg += "- Đã tự động kích hoạt mô hình AI phân tích."

        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Hoàn tất lấy email IMAP",
                "message": notification_msg,
                "type": "success" if total_created > 0 or total_skipped > 0 else "info",
                "sticky": False,
            },
        }

    # ── HÀM DÙNG CHO CRON TỰ ĐỘNG ────────────────────────────────────────

    @api.model
    def cron_fetch_all_active_configs(self):
        """Được gọi bởi cron job để lấy email từ tất cả cấu hình IMAP đang active."""
        active_configs = self.search([("active", "=", True)])
        _logger.info("Bắt đầu cron lấy email IMAP cho %d cấu hình.", len(active_configs))
        for config in active_configs:
            try:
                created_records, skipped, errors = config._fetch_emails()
                _logger.info(
                    "Cron IMAP config '%s': Tạo mới=%d, Trùng=%d, Lỗi=%d",
                    config.name,
                    len(created_records),
                    skipped,
                    errors,
                )
            except Exception as err:
                _logger.error(
                    "Lỗi khi chạy cron IMAP cho config '%s': %s",
                    config.name,
                    err,
                )
