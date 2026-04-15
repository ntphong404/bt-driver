#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
file_manager_gui.py - Giao diện PyQt6 quản lý file bảo mật dùng CAMELLIA driver

Bài tập lớn - Lập trình Driver
Thuật toán: CAMELLIA-CBC 128-bit (qua kernel driver /dev/camellia_drv)

Chức năng:
  - Đăng nhập bảo mật (password hash SHA-256)
  - Mã hóa file đơn / nhiều file (batch processing)
  - Giải mã file đơn / nhiều file (batch processing)
  - Liệt kê file đã mã hóa
  - Xem nội dung file mã hóa (giải mã tạm)
  - Kéo thả file vào giao diện
"""

import sys
import os
import struct
import ctypes
import fcntl
import time
import hashlib
import json
import traceback
import base64
from pathlib import Path
from typing import Optional

try:
    import bcrypt
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("❌ Lỗi: cần cài đặt thư viện 'bcrypt' và 'cryptography'")
    print("   Chạy: pip install bcrypt cryptography")
    sys.exit(1)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QTextEdit, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QMessageBox, QFrame, QSplitter, QGroupBox, QLineEdit,
    QSizePolicy, QAbstractItemView, QStyle, QCheckBox,
    QGraphicsOpacityEffect, QStackedWidget, QDialog
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QSize, QTimer, QPropertyAnimation,
    QEasingCurve, QMimeData, QSequentialAnimationGroup,
    QParallelAnimationGroup, QPoint, QRect
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QIcon, QDragEnterEvent, QDropEvent,
    QLinearGradient, QPainter, QPixmap, QFontDatabase,
    QKeySequence, QShortcut
)

# ===== Hằng số =====
DEVICE_PATH = "/dev/camellia_drv"
CAMELLIA_KEY_SIZE = 16
CAMELLIA_BLOCK_SIZE = 16
CAMELLIA_IOC_MAGIC = ord('K')
ENC_MAGIC = b"CAMF"
ENC_MAGIC_LEN = 4
ENC_EXTENSION = ".enc"
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

# File lưu cấu hình: password_hash (bcrypt) + encryption_key (fixed)
PASSWORD_FILE = os.path.join(os.path.expanduser("~"), ".camellia_vault_pass")
DEFAULT_PASSWORD = "camellia2026"  # Mật khẩu mặc định (chỉ dùng lần đầu, bắt đổi ngay)

# KDF salt - để derive key từ password
KDF_SALT = b"CAMELLIA_VAULT_2026"


def _derive_key_from_password(password: str) -> bytes:
    """Sinh encryption key từ password bằng PBKDF2 (16 bytes)"""
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=CAMELLIA_KEY_SIZE,  # 16 bytes
        salt=KDF_SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def _load_config() -> tuple:
    """
    Đọc cấu hình từ file
    Trả về: (password_hash_bcrypt, encryption_key_bytes, is_first_setup)
    """
    if os.path.isfile(PASSWORD_FILE):
        try:
            with open(PASSWORD_FILE, "r") as f:
                data = json.load(f)
                pw_hash = data.get("password_hash", "").encode() if data.get("password_hash") else None
                enc_key_b64 = data.get("encryption_key", "")
                enc_key = base64.b64decode(enc_key_b64) if enc_key_b64 else None
                
                if pw_hash and enc_key:
                    return pw_hash, enc_key, False
        except Exception:
            pass
    
    # First setup: create default config
    default_key = _derive_key_from_password(DEFAULT_PASSWORD)
    pw_hash = bcrypt.hashpw(DEFAULT_PASSWORD.encode(), bcrypt.gensalt())
    _save_config(pw_hash, default_key)
    return pw_hash, default_key, True


def _save_config(pw_hash_bcrypt: bytes, encryption_key: bytes):
    """
    Lưu cấu hình: password_hash (bcrypt) + encryption_key (fixed)
    
    password_hash: dùng để verify khi login, không thể dịch ngược
    encryption_key: cố định, sinh từ password lần đầu tiên
    """
    try:
        with open(PASSWORD_FILE, "w") as f:
            json.dump({
                "password_hash": pw_hash_bcrypt.decode(),  # bcrypt hash
                "encryption_key": base64.b64encode(encryption_key).decode()  # fixed key
            }, f)
        os.chmod(PASSWORD_FILE, 0o600)  # Chỉ owner đọc/ghi
    except Exception as e:
        print(f"Warning: không ghi được {PASSWORD_FILE}: {e}")

# IOCTL command numbers (phải khớp với driver)
# _IOW(magic, nr, size) = direction(2) << 30 | size(14) << 16 | magic(8) << 8 | nr(8)
# _IOW = 1 << 30, _IOR = 2 << 30
_IOC_WRITE = 1
_IOC_READ = 2


def _IOW(magic, nr, size):
    return (_IOC_WRITE << 30) | (size << 16) | (magic << 8) | nr


def _IOR(magic, nr, size):
    return (_IOC_READ << 30) | (size << 16) | (magic << 8) | nr


# struct camellia_params: key[16] + iv[16] = 32 bytes
PARAMS_SIZE = 32
CAMELLIA_ENCRYPT = _IOW(CAMELLIA_IOC_MAGIC, 1, PARAMS_SIZE)
CAMELLIA_DECRYPT = _IOW(CAMELLIA_IOC_MAGIC, 2, PARAMS_SIZE)
CAMELLIA_GET_LEN = _IOR(CAMELLIA_IOC_MAGIC, 3, ctypes.sizeof(ctypes.c_size_t))

# Khóa mặc định (demo)
# ===== enc_header struct =====
# magic[4] + orig_size(uint32) + iv[16] = 24 bytes
ENC_HEADER_FORMAT = f"<{ENC_MAGIC_LEN}sI{CAMELLIA_KEY_SIZE}s"
ENC_HEADER_SIZE = struct.calcsize(ENC_HEADER_FORMAT)


def padded_size(plain_len: int) -> int:
    """Tính kích thước sau padding PKCS#7"""
    return ((plain_len + CAMELLIA_BLOCK_SIZE) // CAMELLIA_BLOCK_SIZE) * CAMELLIA_BLOCK_SIZE


def gen_random_iv() -> bytes:
    """Sinh IV ngẫu nhiên 16 bytes"""
    return os.urandom(CAMELLIA_KEY_SIZE)


def driver_encrypt(plain: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
    """Gửi plaintext lên driver, nhận ciphertext"""
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
    except OSError as e:
        raise RuntimeError(
            f"Không mở được {DEVICE_PATH}: {e}\n"
            f"Hãy kiểm tra: sudo insmod camellia_drv.ko"
        )

    try:
        # Ghi plaintext vào driver
        n = os.write(fd, plain)
        if n != len(plain):
            raise RuntimeError(f"write() thất bại: ghi {n}/{len(plain)} bytes")

        # Chuẩn bị params: key[16] + iv[16]
        params = key[:CAMELLIA_KEY_SIZE] + iv[:CAMELLIA_KEY_SIZE]

        # IOCTL ENCRYPT
        fcntl.ioctl(fd, CAMELLIA_ENCRYPT, params)

        # Lấy kích thước kết quả
        enc_size = padded_size(len(plain))
        try:
            buf = ctypes.c_size_t(0)
            fcntl.ioctl(fd, CAMELLIA_GET_LEN, buf)
            enc_size = buf.value
        except Exception:
            pass

        # Đọc ciphertext
        # Reset offset (driver đã set f_pos=0 trong ioctl, lseek là dự phòng)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError:
            pass
        cipher = os.read(fd, enc_size)
        if len(cipher) == 0:
            raise RuntimeError("read() trả về 0 bytes")

        return cipher
    finally:
        os.close(fd)


def driver_decrypt(cipher: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
    """Gửi ciphertext lên driver, nhận plaintext"""
    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
    except OSError as e:
        raise RuntimeError(
            f"Không mở được {DEVICE_PATH}: {e}\n"
            f"Hãy kiểm tra: sudo insmod camellia_drv.ko"
        )

    try:
        # Ghi ciphertext vào driver
        n = os.write(fd, cipher)
        if n != len(cipher):
            raise RuntimeError(f"write() thất bại: ghi {n}/{len(cipher)} bytes")

        # Chuẩn bị params
        params = key[:CAMELLIA_KEY_SIZE] + iv[:CAMELLIA_KEY_SIZE]

        # IOCTL DECRYPT
        fcntl.ioctl(fd, CAMELLIA_DECRYPT, params)

        # Lấy kích thước kết quả
        dec_size = len(cipher)
        try:
            buf = ctypes.c_size_t(0)
            fcntl.ioctl(fd, CAMELLIA_GET_LEN, buf)
            dec_size = buf.value
        except Exception:
            pass

        # Đọc plaintext
        try:
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError:
            pass
        plain = os.read(fd, dec_size)
        if len(plain) == 0:
            raise RuntimeError("read() trả về 0 bytes")

        return plain
    finally:
        os.close(fd)


def encrypt_file(input_path: str, key: bytes) -> str:
    """Mã hóa 1 file → file.enc, trả về đường dẫn output"""
    with open(input_path, "rb") as f:
        plain = f.read()

    if len(plain) == 0:
        raise RuntimeError("File rỗng")
    if len(plain) > MAX_FILE_SIZE:
        raise RuntimeError(f"File quá lớn ({len(plain)} bytes > {MAX_FILE_SIZE} bytes)")

    iv = gen_random_iv()
    cipher = driver_encrypt(plain, key, iv)

    out_path = input_path + ENC_EXTENSION
    with open(out_path, "wb") as f:
        header = struct.pack(ENC_HEADER_FORMAT, ENC_MAGIC, len(plain), iv)
        f.write(header)
        f.write(cipher)

    return out_path


def decrypt_file(enc_path: str, key: bytes) -> str:
    """Giải mã file.enc → file gốc, trả về đường dẫn output"""
    with open(enc_path, "rb") as f:
        header_data = f.read(ENC_HEADER_SIZE)
        if len(header_data) < ENC_HEADER_SIZE:
            raise RuntimeError("File quá nhỏ hoặc bị hỏng")

        magic, orig_size, iv = struct.unpack(ENC_HEADER_FORMAT, header_data)
        if magic != ENC_MAGIC:
            raise RuntimeError("Không phải file CAMF (sai magic bytes)")

        cipher = f.read()

    if len(cipher) == 0 or len(cipher) % CAMELLIA_BLOCK_SIZE != 0:
        raise RuntimeError(f"Ciphertext không hợp lệ ({len(cipher)} bytes)")

    plain = driver_decrypt(cipher, key, iv)

    # Cắt về kích thước gốc
    if len(plain) > orig_size:
        plain = plain[:orig_size]

    # Tạo tên output (bỏ .enc)
    if enc_path.endswith(ENC_EXTENSION):
        out_path = enc_path[:-len(ENC_EXTENSION)]
    else:
        out_path = enc_path + ".dec"

    with open(out_path, "wb") as f:
        f.write(plain)

    return out_path


def view_encrypted_file(enc_path: str, key: bytes) -> bytes:
    """Giải mã file.enc và trả về nội dung (không ghi ra file)"""
    with open(enc_path, "rb") as f:
        header_data = f.read(ENC_HEADER_SIZE)
        if len(header_data) < ENC_HEADER_SIZE:
            raise RuntimeError("File quá nhỏ hoặc bị hỏng")

        magic, orig_size, iv = struct.unpack(ENC_HEADER_FORMAT, header_data)
        if magic != ENC_MAGIC:
            raise RuntimeError("Không phải file CAMF")

        cipher = f.read()

    plain = driver_decrypt(cipher, key, iv)
    if len(plain) > orig_size:
        plain = plain[:orig_size]
    return plain


# ═══════════════════════════════════════════════════════════════
#                       WORKER THREAD
# ═══════════════════════════════════════════════════════════════
class CryptoWorker(QThread):
    """Thread xử lý mã hóa/giải mã để không block UI"""
    progress = pyqtSignal(int, int, str)     # current, total, message
    file_done = pyqtSignal(str, str, bool)   # input_path, output_path/error, success
    all_done = pyqtSignal(int, int)          # success_count, total_count

    def __init__(self, files: list, mode: str, key: bytes):
        super().__init__()
        self.files = files
        self.mode = mode  # "encrypt" or "decrypt"
        self.key = key
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        total = len(self.files)
        success = 0

        for i, filepath in enumerate(self.files):
            if self._cancelled:
                break

            name = os.path.basename(filepath)
            action = "Mã hóa" if self.mode == "encrypt" else "Giải mã"
            self.progress.emit(i, total, f"{action}: {name}")

            try:
                if self.mode == "encrypt":
                    out = encrypt_file(filepath, self.key)
                else:
                    out = decrypt_file(filepath, self.key)
                self.file_done.emit(filepath, out, True)
                success += 1
            except Exception as e:
                self.file_done.emit(filepath, str(e), False)

        self.progress.emit(total, total, "Hoàn tất!")
        self.all_done.emit(success, total)


# ═══════════════════════════════════════════════════════════════
#                       LOGIN SCREEN
# ═══════════════════════════════════════════════════════════════
class LoginScreen(QWidget):
    """Màn hình đăng nhập bảo mật"""
    login_success = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._failed_attempts = 0
        self._locked = False
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(0)

        # Spacer trên
        layout.addStretch(2)

        # === Container chính ===
        container = QFrame()
        container.setObjectName("loginContainer")
        container.setFixedSize(420, 480)
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(40, 36, 40, 36)
        container_layout.setSpacing(0)

        # Logo / Icon
        logo = QLabel("🛡️")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("font-size: 56px; margin-bottom: 4px;")
        container_layout.addWidget(logo)

        # Title
        title = QLabel("CAMELLIA Vault")
        title.setObjectName("loginTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(title)

        # Subtitle
        subtitle = QLabel("Hệ thống quản lý file bảo mật")
        subtitle.setObjectName("loginSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(subtitle)

        container_layout.addSpacing(28)

        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("background: #2a3a50; max-height: 1px; margin: 0 20px;")
        container_layout.addWidget(divider)

        container_layout.addSpacing(24)

        # Password label
        pass_label = QLabel("🔑  Mật khẩu truy cập")
        pass_label.setObjectName("loginLabel")
        container_layout.addWidget(pass_label)

        container_layout.addSpacing(8)

        # Password input
        self._password_input = QLineEdit()
        self._password_input.setObjectName("loginInput")
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.setPlaceholderText("Nhập mật khẩu...")
        self._password_input.returnPressed.connect(self._do_login)
        container_layout.addWidget(self._password_input)

        container_layout.addSpacing(8)

        # Show password checkbox
        show_pass_row = QHBoxLayout()
        self._show_pass = QCheckBox("Hiện mật khẩu")
        self._show_pass.setObjectName("showPassCheck")
        self._show_pass.toggled.connect(self._toggle_password_visibility)
        show_pass_row.addWidget(self._show_pass)
        show_pass_row.addStretch()
        container_layout.addLayout(show_pass_row)

        container_layout.addSpacing(16)

        # Login button
        self._btn_login = QPushButton("🔓  ĐĂNG NHẬP")
        self._btn_login.setObjectName("loginBtn")
        self._btn_login.setMinimumHeight(46)
        self._btn_login.clicked.connect(self._do_login)
        self._btn_login.setCursor(Qt.CursorShape.PointingHandCursor)
        container_layout.addWidget(self._btn_login)

        container_layout.addSpacing(12)

        # Error label
        self._error_label = QLabel("")
        self._error_label.setObjectName("loginError")
        self._error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._error_label.setWordWrap(True)
        self._error_label.setVisible(False)
        container_layout.addWidget(self._error_label)

        container_layout.addStretch()

        # Info nhỏ bên dưới
        info = QLabel("CAMELLIA-CBC 128-bit  •  Kernel Crypto API")
        info.setObjectName("loginInfo")
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(info)

        layout.addWidget(container, alignment=Qt.AlignmentFlag.AlignCenter)

        # Spacer dưới
        layout.addStretch(3)

    def _toggle_password_visibility(self, checked):
        if checked:
            self._password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self._password_input.setEchoMode(QLineEdit.EchoMode.Password)

    def _do_login(self):
        if self._locked:
            return

        password = self._password_input.text()
        if not password:
            self._show_error("Vui lòng nhập mật khẩu!")
            return

        # Kiểm tra mật khẩu bằng bcrypt (không thể dịch ngược)
        try:
            # password_hash_bcrypt được lưu từ parent window
            from bai1_crypto_camellia.app.file_manager_gui import CamelliaFileManager
            main_window = self.window() if hasattr(self, 'window') else None
            
            # Lấy pw_hash từ config
            pw_hash_bcrypt, _, _ = _load_config()
            
            # Verify
            if bcrypt.checkpw(password.encode(), pw_hash_bcrypt):
                self._error_label.setVisible(False)
                self.login_success.emit()
            else:
                raise ValueError("Sai mật khẩu")
        except Exception as e:
            self._failed_attempts += 1
            remaining = 5 - self._failed_attempts

            if self._failed_attempts >= 5:
                self._locked = True
                self._show_error("⛔  Đã khóa! Quá nhiều lần nhập sai.")
                self._btn_login.setEnabled(False)
                self._password_input.setEnabled(False)

                # Tự mở khoá sau 30 giây
                QTimer.singleShot(30000, self._unlock)
            else:
                self._show_error(
                    f"❌  Sai mật khẩu! Còn {remaining} lần thử."
                )

            # Hiệu ứng rung
            self._shake_animation()
            self._password_input.clear()
            self._password_input.setFocus()

    def _unlock(self):
        self._locked = False
        self._failed_attempts = 0
        self._btn_login.setEnabled(True)
        self._password_input.setEnabled(True)
        self._error_label.setVisible(False)
        self._password_input.setFocus()

    def _show_error(self, msg: str):
        self._error_label.setText(msg)
        self._error_label.setVisible(True)

    def _shake_animation(self):
        """Hiệu ứng rung khi nhập sai"""
        anim = QPropertyAnimation(self._password_input, b"pos")
        anim.setDuration(400)
        pos = self._password_input.pos()
        anim.setKeyValueAt(0, pos)
        anim.setKeyValueAt(0.1, pos + QPoint(8, 0))
        anim.setKeyValueAt(0.2, pos + QPoint(-8, 0))
        anim.setKeyValueAt(0.3, pos + QPoint(6, 0))
        anim.setKeyValueAt(0.4, pos + QPoint(-6, 0))
        anim.setKeyValueAt(0.5, pos + QPoint(4, 0))
        anim.setKeyValueAt(0.6, pos + QPoint(-4, 0))
        anim.setKeyValueAt(0.7, pos + QPoint(2, 0))
        anim.setKeyValueAt(0.8, pos + QPoint(-2, 0))
        anim.setKeyValueAt(1.0, pos)
        anim.start()
        # Giữ tham chiếu
        self._anim = anim

    def showEvent(self, event):
        super().showEvent(event)
        self._password_input.setFocus()


# ═══════════════════════════════════════════════════════════════
#                    CHANGE PASSWORD DIALOG
# ═══════════════════════════════════════════════════════════════
class ChangePasswordDialog(QDialog):
    """Dialog đổi mật khẩu"""

    def __init__(self, parent=None, is_first_setup=False):
        super().__init__(parent)
        self.setWindowTitle("🔑 Đặt mật khẩu" if is_first_setup else "🔑 Đổi mật khẩu")
        self.setFixedSize(440, 380 if not is_first_setup else 340)
        self.setModal(True)
        self.is_first_setup = is_first_setup
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 24, 30, 24)
        layout.setSpacing(0)

        # Icon + Title
        icon = QLabel("🔑")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("font-size: 40px;")
        layout.addWidget(icon)

        title = QLabel("Đặt mật khẩu" if self.is_first_setup else "Đổi mật khẩu")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            "font-size: 20px; font-weight: bold; color: #e8ecf1; "
            "margin-top: 4px; margin-bottom: 16px;"
        )
        layout.addWidget(title)

        # Old password (hide if first setup)
        if not self.is_first_setup:
            lbl_old = QLabel("Mật khẩu hiện tại")
            lbl_old.setStyleSheet("color: #8094aa; font-size: 12px; font-weight: 500; margin-bottom: 4px;")
            layout.addWidget(lbl_old)

            self._input_old = QLineEdit()
            self._input_old.setEchoMode(QLineEdit.EchoMode.Password)
            self._input_old.setPlaceholderText("Nhập mật khẩu cũ...")
            self._input_old.setObjectName("dialogInput")
            layout.addWidget(self._input_old)

            layout.addSpacing(12)

        # New password
        lbl_new = QLabel("Mật khẩu mới")
        lbl_new.setStyleSheet("color: #8094aa; font-size: 12px; font-weight: 500; margin-bottom: 4px;")
        layout.addWidget(lbl_new)

        self._input_new = QLineEdit()
        self._input_new.setEchoMode(QLineEdit.EchoMode.Password)
        self._input_new.setPlaceholderText("Nhập mật khẩu mới (tối thiểu 4 ký tự)...")
        self._input_new.setObjectName("dialogInput")
        layout.addWidget(self._input_new)

        layout.addSpacing(12)

        # Confirm new password
        lbl_confirm = QLabel("Xác nhận mật khẩu")
        lbl_confirm.setStyleSheet("color: #8094aa; font-size: 12px; font-weight: 500; margin-bottom: 4px;")
        layout.addWidget(lbl_confirm)

        self._input_confirm = QLineEdit()
        self._input_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._input_confirm.setPlaceholderText("Nhập lại mật khẩu mới...")
        self._input_confirm.setObjectName("dialogInput")
        layout.addWidget(self._input_confirm)

        layout.addSpacing(20)

        # Buttons
        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Hủy" if not self.is_first_setup else "Thoát")
        btn_cancel.setObjectName("btnSecondary")
        btn_cancel.clicked.connect(self.reject)

        btn_save = QPushButton("✅  " + ("Đặt lúc này" if self.is_first_setup else "Lưu mật khẩu"))
        btn_save.setObjectName("btnAction")
        btn_save.setMinimumHeight(38)
        btn_save.clicked.connect(self._do_change)

        btn_row.addWidget(btn_cancel)
        btn_row.addStretch()
        btn_row.addWidget(btn_save)
        layout.addLayout(btn_row)

        # Info nếu là first setup
        if self.is_first_setup:
            info = QLabel("💡 Khóa mã hóa sẽ được tạo từ mật khẩu này và không thể thay đổi.")
            info.setStyleSheet("color: #6b7b8d; font-size: 11px; margin-top: 8px; font-style: italic;")
            layout.addWidget(info)

    def _do_change(self):
        old_pw = getattr(self, '_input_old', None)
        new_pw = self._input_new.text()
        confirm_pw = self._input_confirm.text()

        # Verify old password if not first setup
        if not self.is_first_setup:
            if not old_pw.text():
                QMessageBox.warning(self, "Lỗi", "Vui lòng nhập mật khẩu hiện tại!")
                return

            pw_hash_bcrypt, _, _ = _load_config()
            if not bcrypt.checkpw(old_pw.text().encode(), pw_hash_bcrypt):
                QMessageBox.warning(self, "Lỗi", "❌ Mật khẩu hiện tại không đúng!")
                old_pw.clear()
                old_pw.setFocus()
                return

        if len(new_pw) < 4:
            QMessageBox.warning(self, "Lỗi", "Mật khẩu mới phải có tối thiểu 4 ký tự!")
            return

        if new_pw != confirm_pw:
            QMessageBox.warning(self, "Lỗi", "Mật khẩu xác nhận không khớp!")
            self._input_confirm.clear()
            self._input_confirm.setFocus()
            return

        # Only update password hash, NOT encryption key
        pw_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt())
        _, encryption_key, _ = _load_config()
        _save_config(pw_hash, encryption_key)

        msg = "✅ Mật khẩu đã được đặt!" if self.is_first_setup else "✅ Đổi mật khẩu thành công!"
        extra = "\n💡 Khóa mã hóa vẫn không đổi, file cũ vẫn decrypt được." if not self.is_first_setup else ""
        QMessageBox.information(self, "Thành công", msg + extra)
        self.accept()


# ═══════════════════════════════════════════════════════════════
#                       DROP ZONE
# ═══════════════════════════════════════════════════════════════
class DropZone(QFrame):
    """Vùng kéo thả file"""
    files_dropped = pyqtSignal(list)

    def __init__(self, text="Kéo thả file vào đây", parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(120)
        self.default_text = text
        self._label = QLabel(text)
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._label.setStyleSheet("color: #8b95a5; font-size: 14px;")

        self._icon = QLabel("📂")
        self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon.setStyleSheet("font-size: 36px;")

        layout = QVBoxLayout(self)
        layout.addStretch()
        layout.addWidget(self._icon)
        layout.addWidget(self._label)
        layout.addStretch()

        self.setStyleSheet("""
            DropZone {
                border: 2px dashed #3a4556;
                border-radius: 12px;
                background: rgba(30, 37, 48, 0.6);
            }
            DropZone:hover {
                border-color: #546e8a;
                background: rgba(35, 44, 58, 0.8);
            }
        """)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet("""
                DropZone {
                    border: 2px dashed #6cb4ee;
                    border-radius: 12px;
                    background: rgba(40, 60, 90, 0.7);
                }
            """)

    def dragLeaveEvent(self, event):
        self.setStyleSheet("""
            DropZone {
                border: 2px dashed #3a4556;
                border-radius: 12px;
                background: rgba(30, 37, 48, 0.6);
            }
            DropZone:hover {
                border-color: #546e8a;
                background: rgba(35, 44, 58, 0.8);
            }
        """)

    def dropEvent(self, event: QDropEvent):
        self.setStyleSheet("""
            DropZone {
                border: 2px dashed #3a4556;
                border-radius: 12px;
                background: rgba(30, 37, 48, 0.6);
            }
            DropZone:hover {
                border-color: #546e8a;
                background: rgba(35, 44, 58, 0.8);
            }
        """)
        files = []
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                files.append(path)
        if files:
            self.files_dropped.emit(files)


# ═══════════════════════════════════════════════════════════════
#                       MAIN WINDOW
# ═══════════════════════════════════════════════════════════════
class CamelliaFileManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 CAMELLIA File Manager - Bảo Mật")
        self.setMinimumSize(1000, 700)
        self.resize(1100, 780)

        # Load config: password_hash, encryption_key, is_first_setup
        self._pw_hash_bcrypt, self._encryption_key, self._is_first_setup = _load_config()
        self._current_key = self._encryption_key  # KEY cố định
        
        self._worker = None
        self._selected_files = []

        self._setup_ui()
        self._apply_styles()

    def _setup_ui(self):
        """Xây dựng giao diện với Stack: Login → Main"""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Stacked Widget: chuyển Login ↔ Main
        self._stack = QStackedWidget()

        # --- Page 0: Login ---
        self._login_screen = LoginScreen()
        self._login_screen.login_success.connect(self._on_login_success)
        self._stack.addWidget(self._login_screen)

        # --- Page 1: Main App ---
        self._main_page = QWidget()
        self._build_main_page()
        self._stack.addWidget(self._main_page)

        # Mặc định hiện login
        self._stack.setCurrentIndex(0)

        main_layout.addWidget(self._stack)

    def _on_login_success(self):
        """Chuyển sang trang chính sau khi đăng nhập thành công"""
        # Nếu lần đầu setup, bắt đổi mật khẩu
        if self._is_first_setup:
            self._log_msg("⚙️ Lần đầu tiên! Bắt buộc đổi mật khẩu...")
            dialog = ChangePasswordDialog(self, is_first_setup=True)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                new_pw = dialog._input_new.text()
                pw_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt())
                _save_config(pw_hash, self._encryption_key)
                self._pw_hash_bcrypt = pw_hash
                self._is_first_setup = False
                self._stack.setCurrentIndex(1)
                self._log_msg("🔓 Đăng nhập thành công!")
                self._log_msg("✅ Mật khẩu đã được đặt! KEY mã hóa cố định.")
                self._update_driver_status()
            else:
                # Reject = logout
                self._login_screen._password_input.clear()
                self._login_screen._password_input.setFocus()
        else:
            self._stack.setCurrentIndex(1)
            self._log_msg("🔓 Đăng nhập thành công!")
            self._update_driver_status()

    def _build_main_page(self):
        """Xây dựng trang chính (sau login)"""
        layout = QVBoxLayout(self._main_page)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        # === Header ===
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(72)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 0, 24, 0)

        title_icon = QLabel("🔐")
        title_icon.setStyleSheet("font-size: 28px;")
        title = QLabel("CAMELLIA File Manager")
        title.setObjectName("headerTitle")

        subtitle = QLabel("Mã hóa CAMELLIA-CBC 128-bit qua Kernel Driver")
        subtitle.setObjectName("headerSubtitle")

        # Driver status indicator
        self._driver_status = QLabel()
        self._driver_status.setObjectName("driverStatus")
        self._update_driver_status()

        # User info
        user_info = QLabel("👤 User: Đã xác thực")
        user_info.setStyleSheet(
            "color: #4ade80; font-size: 11px; font-weight: bold; "
            "padding: 4px 10px; background: rgba(74, 222, 128, 0.08); "
            "border-radius: 10px; border: 1px solid rgba(74, 222, 128, 0.2);"
        )

        # Settings (change password) button
        btn_settings = QPushButton("⚙️ Cài đặt")
        btn_settings.setObjectName("btnSettings")
        btn_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_settings.clicked.connect(self._open_change_password)

        # Logout button
        btn_logout = QPushButton("🚪 Đăng xuất")
        btn_logout.setObjectName("btnLogout")
        btn_logout.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_logout.clicked.connect(self._logout)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_col.addWidget(title)
        title_col.addWidget(subtitle)

        header_layout.addWidget(title_icon)
        header_layout.addSpacing(12)
        header_layout.addLayout(title_col)
        header_layout.addStretch()
        header_layout.addWidget(self._driver_status)
        header_layout.addSpacing(8)
        header_layout.addWidget(user_info)
        header_layout.addSpacing(6)
        header_layout.addWidget(btn_settings)
        header_layout.addSpacing(6)
        header_layout.addWidget(btn_logout)

        layout.addWidget(header)

        # === Body ===
        body = QWidget()
        body.setObjectName("body")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(20, 16, 20, 16)
        body_layout.setSpacing(12)

        # Tab widget
        self._tabs = QTabWidget()
        self._tabs.setObjectName("mainTabs")

        # --- Tab 1: Mã hóa ---
        encrypt_tab = self._create_encrypt_tab()
        self._tabs.addTab(encrypt_tab, "🔒  Mã hóa")

        # --- Tab 2: Giải mã ---
        decrypt_tab = self._create_decrypt_tab()
        self._tabs.addTab(decrypt_tab, "🔓  Giải mã")

        # --- Tab 3: Quản lý file ---
        browse_tab = self._create_browse_tab()
        self._tabs.addTab(browse_tab, "📁  Quản lý")

        # --- Tab 4: Xem nội dung ---
        view_tab = self._create_view_tab()
        self._tabs.addTab(view_tab, "👁  Xem file")

        body_layout.addWidget(self._tabs)

        # === Progress bar ===
        progress_frame = QFrame()
        progress_frame.setObjectName("progressFrame")
        progress_layout = QVBoxLayout(progress_frame)
        progress_layout.setContentsMargins(0, 8, 0, 0)
        progress_layout.setSpacing(4)

        self._progress_label = QLabel("")
        self._progress_label.setObjectName("progressLabel")
        self._progress_bar = QProgressBar()
        self._progress_bar.setObjectName("progressBar")
        self._progress_bar.setVisible(False)
        self._progress_label.setVisible(False)

        progress_layout.addWidget(self._progress_label)
        progress_layout.addWidget(self._progress_bar)

        body_layout.addWidget(progress_frame)

        # === Log console ===
        self._log = QTextEdit()
        self._log.setObjectName("logConsole")
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(150)
        self._log.setPlaceholderText("Nhật ký hoạt động...")

        body_layout.addWidget(self._log)
        layout.addWidget(body, 1)

        # === Footer ===
        footer = QFrame()
        footer.setObjectName("footer")
        footer.setFixedHeight(36)
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(24, 0, 24, 0)
        footer_lbl = QLabel("CAMELLIA-CBC 128-bit  •  Kernel Crypto API  •  Bài tập lớn Lập trình Driver")
        footer_lbl.setObjectName("footerLabel")
        footer_layout.addStretch()
        footer_layout.addWidget(footer_lbl)
        footer_layout.addStretch()
        layout.addWidget(footer)

        # Timer kiểm tra driver
        self._status_timer = QTimer()
        self._status_timer.timeout.connect(self._update_driver_status)
        self._status_timer.start(5000)

    def _logout(self):
        """Đăng xuất và quay lai màn hình login"""
        reply = QMessageBox.question(
            self, "Đăng xuất",
            "Bạn có chắc muốn đăng xuất?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._login_screen._password_input.clear()
            self._stack.setCurrentIndex(0)
            self._login_screen._password_input.setFocus()

    def _open_change_password(self):
        """Mở dialog đổi mật khẩu"""
        dialog = ChangePasswordDialog(self, is_first_setup=False)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._log_msg("🔑 Đã đổi mật khẩu thành công!")

    def _create_encrypt_tab(self) -> QWidget:
        """Tab mã hóa file"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)

        # Drop zone
        self._enc_drop = DropZone("Kéo thả file cần mã hóa vào đây\nhoặc nhấn nút bên dưới")
        self._enc_drop.files_dropped.connect(self._enc_files_dropped)
        layout.addWidget(self._enc_drop)

        # File list
        self._enc_table = QTableWidget()
        self._enc_table.setColumnCount(3)
        self._enc_table.setHorizontalHeaderLabels(["Tên file", "Kích thước", "Trạng thái"])
        self._enc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._enc_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._enc_table.horizontalHeader().resizeSection(1, 120)
        self._enc_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self._enc_table.horizontalHeader().resizeSection(2, 160)
        self._enc_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._enc_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._enc_table.verticalHeader().setVisible(False)
        layout.addWidget(self._enc_table)

        # File count label
        self._enc_count_label = QLabel("📊 Chưa có file nào")
        self._enc_count_label.setStyleSheet("color: #6b7b8d; font-size: 12px; font-style: italic;")
        layout.addWidget(self._enc_count_label)

        # Buttons
        btn_layout = QHBoxLayout()

        btn_add = QPushButton("➕  Thêm file")
        btn_add.setObjectName("btnPrimary")
        btn_add.clicked.connect(self._enc_add_files)

        btn_add_folder = QPushButton("📁  Thêm thư mục")
        btn_add_folder.setObjectName("btnSecondary")
        btn_add_folder.clicked.connect(self._enc_add_folder)

        btn_clear = QPushButton("🗑  Xóa danh sách")
        btn_clear.setObjectName("btnDanger")
        btn_clear.clicked.connect(self._enc_clear)

        btn_remove = QPushButton("✖  Xóa đã chọn")
        btn_remove.setObjectName("btnSecondary")
        btn_remove.clicked.connect(self._enc_remove_selected)

        btn_encrypt = QPushButton("🔒  MÃ HÓA TẤT CẢ")
        btn_encrypt.setObjectName("btnAction")
        btn_encrypt.setMinimumHeight(40)
        btn_encrypt.clicked.connect(self._enc_start)

        btn_layout.addWidget(btn_add)
        btn_layout.addWidget(btn_add_folder)
        btn_layout.addWidget(btn_remove)
        btn_layout.addWidget(btn_clear)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_encrypt)

        layout.addLayout(btn_layout)

        # Internal file list
        self._enc_files = []

        return tab

    def _create_decrypt_tab(self) -> QWidget:
        """Tab giải mã file"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)

        # Drop zone
        self._dec_drop = DropZone("Kéo thả file .enc cần giải mã vào đây\nhoặc nhấn nút bên dưới")
        self._dec_drop.files_dropped.connect(self._dec_files_dropped)
        layout.addWidget(self._dec_drop)

        # File list
        self._dec_table = QTableWidget()
        self._dec_table.setColumnCount(3)
        self._dec_table.setHorizontalHeaderLabels(["Tên file", "Kích thước", "Trạng thái"])
        self._dec_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._dec_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._dec_table.horizontalHeader().resizeSection(1, 120)
        self._dec_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self._dec_table.horizontalHeader().resizeSection(2, 160)
        self._dec_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._dec_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._dec_table.verticalHeader().setVisible(False)
        layout.addWidget(self._dec_table)

        # File count label
        self._dec_count_label = QLabel("📊 Chưa có file nào")
        self._dec_count_label.setStyleSheet("color: #6b7b8d; font-size: 12px; font-style: italic;")
        layout.addWidget(self._dec_count_label)

        # Buttons
        btn_layout = QHBoxLayout()

        btn_add = QPushButton("➕  Thêm file .enc")
        btn_add.setObjectName("btnPrimary")
        btn_add.clicked.connect(self._dec_add_files)

        btn_add_folder = QPushButton("📁  Thêm thư mục")
        btn_add_folder.setObjectName("btnSecondary")
        btn_add_folder.clicked.connect(self._dec_add_folder)

        btn_clear = QPushButton("🗑  Xóa danh sách")
        btn_clear.setObjectName("btnDanger")
        btn_clear.clicked.connect(self._dec_clear)

        btn_remove = QPushButton("✖  Xóa đã chọn")
        btn_remove.setObjectName("btnSecondary")
        btn_remove.clicked.connect(self._dec_remove_selected)

        btn_decrypt = QPushButton("🔓  GIẢI MÃ TẤT CẢ")
        btn_decrypt.setObjectName("btnAction")
        btn_decrypt.setMinimumHeight(40)
        btn_decrypt.clicked.connect(self._dec_start)

        btn_layout.addWidget(btn_add)
        btn_layout.addWidget(btn_add_folder)
        btn_layout.addWidget(btn_remove)
        btn_layout.addWidget(btn_clear)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_decrypt)

        layout.addLayout(btn_layout)

        self._dec_files = []

        return tab

    def _create_browse_tab(self) -> QWidget:
        """Tab quản lý / liệt kê file .enc"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)

        # Toolbar
        toolbar = QHBoxLayout()
        dir_label = QLabel("Thư mục:")
        dir_label.setStyleSheet("color: #c0c8d4; font-size: 13px;")
        self._browse_dir = QLineEdit()
        self._browse_dir.setObjectName("dirInput")
        self._browse_dir.setPlaceholderText("Nhập đường dẫn thư mục...")
        self._browse_dir.setText(os.getcwd())

        btn_browse = QPushButton("📂  Chọn")
        btn_browse.setObjectName("btnSecondary")
        btn_browse.clicked.connect(self._browse_choose_dir)

        btn_scan = QPushButton("🔍  Quét")
        btn_scan.setObjectName("btnPrimary")
        btn_scan.clicked.connect(self._browse_scan)

        toolbar.addWidget(dir_label)
        toolbar.addWidget(self._browse_dir, 1)
        toolbar.addWidget(btn_browse)
        toolbar.addWidget(btn_scan)
        layout.addLayout(toolbar)

        # File table
        self._browse_table = QTableWidget()
        self._browse_table.setColumnCount(4)
        self._browse_table.setHorizontalHeaderLabels(
            ["Tên file", "Kích thước gốc", "Kích thước .enc", "Đường dẫn"]
        )
        self._browse_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._browse_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._browse_table.horizontalHeader().resizeSection(1, 120)
        self._browse_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self._browse_table.horizontalHeader().resizeSection(2, 120)
        self._browse_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._browse_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._browse_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._browse_table.verticalHeader().setVisible(False)
        self._browse_table.doubleClicked.connect(self._browse_view_file)
        layout.addWidget(self._browse_table)

        # Actions
        action_layout = QHBoxLayout()
        btn_view = QPushButton("👁  Xem nội dung")
        btn_view.setObjectName("btnPrimary")
        btn_view.clicked.connect(self._browse_view_selected)

        btn_dec = QPushButton("🔓  Giải mã đã chọn")
        btn_dec.setObjectName("btnAction")
        btn_dec.clicked.connect(self._browse_decrypt_selected)

        info_lbl = QLabel("💡 Nhấp đúp vào file để xem nội dung")
        info_lbl.setStyleSheet("color: #6b7b8d; font-size: 12px; font-style: italic;")

        action_layout.addWidget(info_lbl)
        action_layout.addStretch()
        action_layout.addWidget(btn_view)
        action_layout.addWidget(btn_dec)
        layout.addLayout(action_layout)

        return tab

    def _create_view_tab(self) -> QWidget:
        """Tab xem nội dung file mã hóa"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)

        # Toolbar
        toolbar = QHBoxLayout()
        self._view_path = QLineEdit()
        self._view_path.setObjectName("dirInput")
        self._view_path.setPlaceholderText("Chọn file .enc để xem nội dung...")
        self._view_path.setReadOnly(True)

        btn_choose = QPushButton("📂  Chọn file")
        btn_choose.setObjectName("btnPrimary")
        btn_choose.clicked.connect(self._view_choose_file)

        btn_view = QPushButton("👁  Xem")
        btn_view.setObjectName("btnAction")
        btn_view.clicked.connect(self._view_show)

        toolbar.addWidget(self._view_path, 1)
        toolbar.addWidget(btn_choose)
        toolbar.addWidget(btn_view)
        layout.addLayout(toolbar)

        # File info
        self._view_info = QLabel("")
        self._view_info.setObjectName("viewInfo")
        self._view_info.setWordWrap(True)
        layout.addWidget(self._view_info)

        # Content viewer
        self._view_content = QTextEdit()
        self._view_content.setObjectName("viewContent")
        self._view_content.setReadOnly(True)
        self._view_content.setPlaceholderText("Nội dung file sẽ hiển thị ở đây...")
        layout.addWidget(self._view_content, 1)

        return tab

    # ===== Encrypt tab handlers =====
    def _enc_files_dropped(self, files):
        for f in files:
            if f not in self._enc_files:
                self._enc_files.append(f)
        self._enc_refresh_table()

    def _enc_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Chọn file để mã hóa", os.getcwd(), "Tất cả (*)"
        )
        for f in files:
            if f not in self._enc_files:
                self._enc_files.append(f)
        self._enc_refresh_table()

    def _enc_add_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Chọn thư mục", os.getcwd()
        )
        if folder:
            for name in os.listdir(folder):
                path = os.path.join(folder, name)
                if os.path.isfile(path) and not name.endswith(ENC_EXTENSION):
                    if path not in self._enc_files:
                        self._enc_files.append(path)
            self._enc_refresh_table()

    def _enc_clear(self):
        self._enc_files.clear()
        self._enc_refresh_table()

    def _enc_remove_selected(self):
        rows = set()
        for item in self._enc_table.selectedItems():
            rows.add(item.row())
        for row in sorted(rows, reverse=True):
            if 0 <= row < len(self._enc_files):
                self._enc_files.pop(row)
        self._enc_refresh_table()

    def _enc_refresh_table(self):
        self._enc_table.setRowCount(len(self._enc_files))
        total_size = 0
        for i, filepath in enumerate(self._enc_files):
            name = os.path.basename(filepath)
            try:
                size = os.path.getsize(filepath)
                size_str = self._format_size(size)
                total_size += size
            except OSError:
                size_str = "?"

            self._enc_table.setItem(i, 0, QTableWidgetItem(name))
            self._enc_table.setItem(i, 1, QTableWidgetItem(size_str))
            self._enc_table.setItem(i, 2, QTableWidgetItem("⏳ Đang chờ"))

        count = len(self._enc_files)
        if count > 0:
            self._enc_count_label.setText(
                f"📊 {count} file  •  Tổng: {self._format_size(total_size)}"
            )
        else:
            self._enc_count_label.setText("📊 Chưa có file nào")

    def _enc_start(self):
        if not self._enc_files:
            QMessageBox.warning(self, "Cảnh báo", "Chưa có file nào để mã hóa!")
            return
        if self._worker and self._worker.isRunning():
            QMessageBox.warning(self, "Cảnh báo", "Đang xử lý, vui lòng đợi...")
            return

        self._log_msg("═" * 50)
        self._log_msg(f"🔒 Bắt đầu mã hóa {len(self._enc_files)} file...")

        self._progress_bar.setVisible(True)
        self._progress_label.setVisible(True)
        self._progress_bar.setMaximum(len(self._enc_files))
        self._progress_bar.setValue(0)

        self._worker = CryptoWorker(self._enc_files.copy(), "encrypt", self._current_key)
        self._worker.progress.connect(self._on_progress)
        self._worker.file_done.connect(lambda inp, out, ok: self._on_file_done(inp, out, ok, self._enc_table, self._enc_files))
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    # ===== Decrypt tab handlers =====
    def _dec_files_dropped(self, files):
        for f in files:
            if f.endswith(ENC_EXTENSION) and f not in self._dec_files:
                self._dec_files.append(f)
        self._dec_refresh_table()

    def _dec_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Chọn file .enc để giải mã", os.getcwd(),
            "File mã hóa (*.enc);;Tất cả (*)"
        )
        for f in files:
            if f not in self._dec_files:
                self._dec_files.append(f)
        self._dec_refresh_table()

    def _dec_add_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Chọn thư mục chứa file .enc", os.getcwd()
        )
        if folder:
            for name in os.listdir(folder):
                if name.endswith(ENC_EXTENSION):
                    path = os.path.join(folder, name)
                    if os.path.isfile(path) and path not in self._dec_files:
                        self._dec_files.append(path)
            self._dec_refresh_table()

    def _dec_clear(self):
        self._dec_files.clear()
        self._dec_refresh_table()

    def _dec_remove_selected(self):
        rows = set()
        for item in self._dec_table.selectedItems():
            rows.add(item.row())
        for row in sorted(rows, reverse=True):
            if 0 <= row < len(self._dec_files):
                self._dec_files.pop(row)
        self._dec_refresh_table()

    def _dec_refresh_table(self):
        self._dec_table.setRowCount(len(self._dec_files))
        total_size = 0
        for i, filepath in enumerate(self._dec_files):
            name = os.path.basename(filepath)
            try:
                size = os.path.getsize(filepath)
                size_str = self._format_size(size)
                total_size += size
            except OSError:
                size_str = "?"

            self._dec_table.setItem(i, 0, QTableWidgetItem(name))
            self._dec_table.setItem(i, 1, QTableWidgetItem(size_str))
            self._dec_table.setItem(i, 2, QTableWidgetItem("⏳ Đang chờ"))

        count = len(self._dec_files)
        if count > 0:
            self._dec_count_label.setText(
                f"📊 {count} file  •  Tổng: {self._format_size(total_size)}"
            )
        else:
            self._dec_count_label.setText("📊 Chưa có file nào")

    def _dec_start(self):
        if not self._dec_files:
            QMessageBox.warning(self, "Cảnh báo", "Chưa có file nào để giải mã!")
            return
        if self._worker and self._worker.isRunning():
            QMessageBox.warning(self, "Cảnh báo", "Đang xử lý, vui lòng đợi...")
            return

        self._log_msg("═" * 50)
        self._log_msg(f"🔓 Bắt đầu giải mã {len(self._dec_files)} file...")

        self._progress_bar.setVisible(True)
        self._progress_label.setVisible(True)
        self._progress_bar.setMaximum(len(self._dec_files))
        self._progress_bar.setValue(0)

        self._worker = CryptoWorker(self._dec_files.copy(), "decrypt", self._current_key)
        self._worker.progress.connect(self._on_progress)
        self._worker.file_done.connect(lambda inp, out, ok: self._on_file_done(inp, out, ok, self._dec_table, self._dec_files))
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    # ===== Browse tab handlers =====
    def _browse_choose_dir(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Chọn thư mục", self._browse_dir.text() or os.getcwd()
        )
        if folder:
            self._browse_dir.setText(folder)
            self._browse_scan()

    def _browse_scan(self):
        dir_path = self._browse_dir.text().strip()
        if not dir_path or not os.path.isdir(dir_path):
            QMessageBox.warning(self, "Lỗi", "Thư mục không hợp lệ!")
            return

        self._browse_table.setRowCount(0)
        count = 0

        for name in sorted(os.listdir(dir_path)):
            if not name.endswith(ENC_EXTENSION):
                continue
            full_path = os.path.join(dir_path, name)
            if not os.path.isfile(full_path):
                continue

            enc_size = os.path.getsize(full_path)
            orig_size_str = "?"

            # Đọc header để lấy kích thước gốc
            try:
                with open(full_path, "rb") as f:
                    hdr_data = f.read(ENC_HEADER_SIZE)
                    if len(hdr_data) == ENC_HEADER_SIZE:
                        magic, orig_size, _ = struct.unpack(ENC_HEADER_FORMAT, hdr_data)
                        if magic == ENC_MAGIC:
                            orig_size_str = self._format_size(orig_size)
            except Exception:
                pass

            row = self._browse_table.rowCount()
            self._browse_table.insertRow(row)
            self._browse_table.setItem(row, 0, QTableWidgetItem(name))
            self._browse_table.setItem(row, 1, QTableWidgetItem(orig_size_str))
            self._browse_table.setItem(row, 2, QTableWidgetItem(self._format_size(enc_size)))

            path_item = QTableWidgetItem(full_path)
            self._browse_table.setItem(row, 3, path_item)
            count += 1

        self._log_msg(f"📁 Tìm thấy {count} file .enc trong {dir_path}")

    def _browse_view_file(self, index):
        row = index.row()
        path_item = self._browse_table.item(row, 3)
        if path_item:
            self._view_path.setText(path_item.text())
            self._tabs.setCurrentIndex(3)  # Switch to view tab
            self._view_show()

    def _browse_view_selected(self):
        rows = set()
        for item in self._browse_table.selectedItems():
            rows.add(item.row())
        if not rows:
            QMessageBox.information(self, "Thông báo", "Hãy chọn file cần xem!")
            return
        row = min(rows)
        path_item = self._browse_table.item(row, 3)
        if path_item:
            self._view_path.setText(path_item.text())
            self._tabs.setCurrentIndex(3)
            self._view_show()

    def _browse_decrypt_selected(self):
        rows = set()
        for item in self._browse_table.selectedItems():
            rows.add(item.row())
        if not rows:
            QMessageBox.information(self, "Thông báo", "Hãy chọn file cần giải mã!")
            return

        files = []
        for row in rows:
            path_item = self._browse_table.item(row, 3)
            if path_item:
                files.append(path_item.text())

        if files:
            self._dec_files = files
            self._dec_refresh_table()
            self._tabs.setCurrentIndex(1)  # Switch to decrypt tab
            self._dec_start()

    # ===== View tab handlers =====
    def _view_choose_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Chọn file .enc", os.getcwd(),
            "File mã hóa (*.enc);;Tất cả (*)"
        )
        if path:
            self._view_path.setText(path)
            self._view_show()

    def _view_show(self):
        path = self._view_path.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Lỗi", "File không hợp lệ!")
            return

        try:
            # Đọc header
            with open(path, "rb") as f:
                hdr_data = f.read(ENC_HEADER_SIZE)
                magic, orig_size, iv = struct.unpack(ENC_HEADER_FORMAT, hdr_data)

            if magic != ENC_MAGIC:
                self._view_info.setText("❌ Không phải file CAMF!")
                return

            iv_hex = iv.hex().upper()
            enc_size = os.path.getsize(path)

            self._view_info.setText(
                f"📄 <b>File:</b> {os.path.basename(path)}&nbsp;&nbsp;│&nbsp;&nbsp;"
                f"📏 <b>Gốc:</b> {self._format_size(orig_size)}&nbsp;&nbsp;│&nbsp;&nbsp;"
                f"🔒 <b>Enc:</b> {self._format_size(enc_size)}&nbsp;&nbsp;│&nbsp;&nbsp;"
                f"🔑 <b>IV:</b> <code>{iv_hex[:16]}...</code>"
            )

            # Giải mã để xem
            content = view_encrypted_file(path, self._current_key)

            # Thử hiển thị dưới dạng text
            try:
                text = content.decode("utf-8")
                self._view_content.setPlainText(text)
            except UnicodeDecodeError:
                # Hiển thị hex dump
                hex_lines = []
                for i in range(0, min(len(content), 2048), 16):
                    chunk = content[i:i + 16]
                    hex_part = " ".join(f"{b:02X}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    hex_lines.append(f"{i:08X}  {hex_part:<48s}  {ascii_part}")
                if len(content) > 2048:
                    hex_lines.append(f"\n... ({len(content)} bytes total)")
                self._view_content.setPlainText("\n".join(hex_lines))

            self._log_msg(f"👁 Đã xem: {os.path.basename(path)} ({self._format_size(orig_size)})")

        except Exception as e:
            self._view_content.setPlainText(f"❌ Lỗi: {e}")
            self._log_msg(f"❌ Lỗi xem file: {e}")

    # ===== Progress handlers =====
    def _on_progress(self, current, total, message):
        self._progress_bar.setValue(current)
        self._progress_label.setText(message)

    def _on_file_done(self, input_path, output_or_error, success, table, file_list):
        name = os.path.basename(input_path)
        try:
            idx = file_list.index(input_path)
        except ValueError:
            return

        if success:
            out_name = os.path.basename(output_or_error)
            table.setItem(idx, 2, QTableWidgetItem("✅ Thành công"))
            self._log_msg(f"  ✅ {name} → {out_name}")
        else:
            item = QTableWidgetItem(f"❌ {output_or_error[:40]}")
            table.setItem(idx, 2, item)
            self._log_msg(f"  ❌ {name}: {output_or_error}")

    def _on_all_done(self, success, total):
        self._progress_bar.setVisible(False)
        self._progress_label.setVisible(False)
        fails = total - success
        emoji = "🎉" if fails == 0 else "⚠️"
        self._log_msg(f"{emoji} Hoàn tất: {success}/{total} thành công" +
                      (f", {fails} thất bại" if fails else ""))

        QMessageBox.information(
            self, "Hoàn tất",
            f"Đã xử lý: {success}/{total} file thành công!" +
            (f"\n{fails} file thất bại." if fails else "")
        )

    # ===== Helpers =====
    def _update_driver_status(self):
        if os.path.exists(DEVICE_PATH):
            try:
                fd = os.open(DEVICE_PATH, os.O_RDWR)
                os.close(fd)
                self._driver_status.setText("🟢  Driver: Sẵn sàng")
                self._driver_status.setStyleSheet(
                    "color: #4ade80; font-size: 12px; font-weight: bold; "
                    "padding: 4px 12px; background: rgba(74, 222, 128, 0.1); "
                    "border-radius: 10px;"
                )
            except PermissionError:
                self._driver_status.setText("🟡  Driver: Cần quyền root")
                self._driver_status.setStyleSheet(
                    "color: #facc15; font-size: 12px; font-weight: bold; "
                    "padding: 4px 12px; background: rgba(250, 204, 21, 0.1); "
                    "border-radius: 10px;"
                )
            except OSError:
                self._driver_status.setText("🔴  Driver: Lỗi")
                self._driver_status.setStyleSheet(
                    "color: #f87171; font-size: 12px; font-weight: bold; "
                    "padding: 4px 12px; background: rgba(248, 113, 113, 0.1); "
                    "border-radius: 10px;"
                )
        else:
            self._driver_status.setText("🔴  Driver: Chưa tải")
            self._driver_status.setStyleSheet(
                "color: #f87171; font-size: 12px; font-weight: bold; "
                "padding: 4px 12px; background: rgba(248, 113, 113, 0.1); "
                "border-radius: 10px;"
            )

    def _log_msg(self, msg: str):
        timestamp = time.strftime("%H:%M:%S")
        self._log.append(f"<span style='color:#546e8a'>[{timestamp}]</span> {msg}")

    @staticmethod
    def _format_size(size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"

    def _apply_styles(self):
        """Áp dụng stylesheet toàn cục"""
        self.setStyleSheet("""
            /* ===== Global ===== */
            QMainWindow {
                background: #0f1419;
            }

            QWidget {
                font-family: "Segoe UI", "Cantarell", "Ubuntu", sans-serif;
                color: #d0d7e1;
            }

            /* ═══════════════════════════════════════
               LOGIN SCREEN
               ═══════════════════════════════════════ */
            #loginContainer {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(22, 30, 42, 0.95),
                    stop:0.5 rgba(18, 25, 36, 0.98),
                    stop:1 rgba(14, 20, 30, 0.95));
                border: 1px solid rgba(60, 85, 120, 0.35);
                border-radius: 20px;
            }

            #loginTitle {
                font-size: 26px;
                font-weight: bold;
                color: #e8ecf1;
                letter-spacing: 1.5px;
                margin-top: 4px;
            }

            #loginSubtitle {
                font-size: 12px;
                color: #6b7b8d;
                letter-spacing: 0.4px;
                margin-bottom: 4px;
            }

            #loginLabel {
                font-size: 13px;
                color: #8094aa;
                font-weight: 500;
                letter-spacing: 0.3px;
            }

            #loginInput {
                background: rgba(10, 14, 20, 0.8);
                color: #e0e7f0;
                border: 1px solid #2a3a50;
                border-radius: 10px;
                padding: 12px 16px;
                font-size: 14px;
                letter-spacing: 0.5px;
            }
            #loginInput:focus {
                border-color: #4a80c0;
                background: rgba(12, 16, 24, 0.9);
            }

            #showPassCheck {
                color: #6b7b8d;
                font-size: 11px;
                spacing: 6px;
            }
            #showPassCheck::indicator {
                width: 14px;
                height: 14px;
                border: 1px solid #3a4a60;
                border-radius: 3px;
                background: rgba(10, 14, 20, 0.6);
            }
            #showPassCheck::indicator:checked {
                background: #2a6ab0;
                border-color: #4a8ad0;
            }

            #loginBtn {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a5fa0, stop:0.5 #2472b8, stop:1 #2878c8);
                color: #ffffff;
                font-size: 15px;
                font-weight: bold;
                padding: 12px 28px;
                border: none;
                border-radius: 10px;
                letter-spacing: 1px;
            }
            #loginBtn:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2070b8, stop:0.5 #3088d0, stop:1 #3890d8);
            }
            #loginBtn:pressed {
                background: #144a80;
            }
            #loginBtn:disabled {
                background: #2a3040;
                color: #5a6578;
            }

            #loginError {
                color: #f08080;
                font-size: 12px;
                font-weight: 500;
                padding: 6px 12px;
                background: rgba(240, 80, 80, 0.08);
                border: 1px solid rgba(240, 80, 80, 0.2);
                border-radius: 8px;
            }

            #loginInfo {
                color: #3a4a60;
                font-size: 10px;
                letter-spacing: 0.3px;
            }

            /* ═══════════════════════════════════════
               HEADER
               ═══════════════════════════════════════ */
            #header {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a1f2e, stop:0.5 #1e2a3a, stop:1 #1a1f2e);
                border-bottom: 1px solid #2a3545;
            }

            #headerTitle {
                font-size: 20px;
                font-weight: bold;
                color: #e8ecf1;
                letter-spacing: 0.5px;
            }

            #btnSettings {
                background: rgba(108, 180, 238, 0.08);
                color: #8ec5f0;
                border: 1px solid rgba(108, 180, 238, 0.2);
                border-radius: 8px;
                padding: 5px 14px;
                font-size: 11px;
                font-weight: 500;
            }
            #btnSettings:hover {
                background: rgba(108, 180, 238, 0.15);
                border-color: rgba(108, 180, 238, 0.35);
            }

            #headerSubtitle {
                font-size: 11px;
                color: #6b7b8d;
                letter-spacing: 0.3px;
            }

            #btnLogout {
                background: rgba(240, 80, 80, 0.08);
                color: #f08080;
                border: 1px solid rgba(240, 80, 80, 0.2);
                border-radius: 8px;
                padding: 5px 14px;
                font-size: 11px;
                font-weight: 500;
            }
            #btnLogout:hover {
                background: rgba(240, 80, 80, 0.15);
                border-color: rgba(240, 80, 80, 0.35);
            }

            /* ===== Footer ===== */
            #footer {
                background: #0d1117;
                border-top: 1px solid #1e2733;
            }

            #footerLabel {
                font-size: 10px;
                color: #4a5568;
                letter-spacing: 0.2px;
            }

            /* ===== Body ===== */
            #body {
                background: #0f1419;
            }

            /* ===== Tabs ===== */
            #mainTabs {
                background: transparent;
            }

            QTabWidget::pane {
                background: #151b23;
                border: 1px solid #222d3a;
                border-radius: 8px;
                border-top-left-radius: 0px;
                top: -1px;
            }

            QTabBar::tab {
                background: #1a2030;
                color: #7b8a9d;
                padding: 10px 22px;
                margin-right: 2px;
                border: 1px solid #222d3a;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-size: 13px;
                font-weight: 500;
            }

            QTabBar::tab:selected {
                background: #151b23;
                color: #e0e7f0;
                border-bottom: 2px solid #6cb4ee;
            }

            QTabBar::tab:hover:!selected {
                background: #1e2838;
                color: #a0b0c4;
            }

            /* ===== Tables ===== */
            QTableWidget {
                background: #131920;
                alternate-background-color: #161d26;
                border: 1px solid #222d3a;
                border-radius: 6px;
                gridline-color: #1e2733;
                selection-background-color: rgba(108, 180, 238, 0.15);
                selection-color: #e0e7f0;
                font-size: 12px;
            }

            QTableWidget::item {
                padding: 6px 10px;
                border-bottom: 1px solid #1a2230;
            }

            QHeaderView::section {
                background: #1a2030;
                color: #8094aa;
                padding: 8px 10px;
                border: none;
                border-bottom: 2px solid #2a3545;
                border-right: 1px solid #222d3a;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            /* ===== Buttons ===== */
            QPushButton {
                padding: 8px 16px;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 500;
                border: 1px solid transparent;
            }

            #btnPrimary {
                background: #1e3a5f;
                color: #8ec5f0;
                border: 1px solid #2a4a70;
            }
            #btnPrimary:hover {
                background: #264a73;
                border-color: #3a6090;
            }
            #btnPrimary:pressed {
                background: #163050;
            }

            #btnSecondary {
                background: #1e2535;
                color: #8b95a5;
                border: 1px solid #2a3545;
            }
            #btnSecondary:hover {
                background: #253040;
                color: #a0b0c4;
            }

            #btnDanger {
                background: #3a1a1a;
                color: #f08080;
                border: 1px solid #4a2525;
            }
            #btnDanger:hover {
                background: #4a2020;
            }

            #btnAction {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a5fa0, stop:1 #2878c8);
                color: #ffffff;
                font-size: 13px;
                font-weight: bold;
                padding: 10px 28px;
                border: none;
                letter-spacing: 0.5px;
            }
            #btnAction:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2070b8, stop:1 #3090e0);
            }
            #btnAction:pressed {
                background: #144a80;
            }

            /* ===== Inputs ===== */
            #dirInput {
                background: #131920;
                color: #d0d7e1;
                border: 1px solid #2a3545;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
            }
            #dirInput:focus {
                border-color: #4a7aaa;
            }

            /* ===== Progress ===== */
            #progressBar {
                background: #1a2030;
                border: 1px solid #2a3545;
                border-radius: 4px;
                height: 8px;
                text-align: center;
            }
            #progressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3a80c0, stop:1 #50b0f0);
                border-radius: 3px;
            }

            #progressLabel {
                font-size: 11px;
                color: #8094aa;
            }

            /* ===== Log ===== */
            #logConsole {
                background: #0d1117;
                color: #8b95a5;
                border: 1px solid #1e2733;
                border-radius: 6px;
                padding: 8px;
                font-family: "JetBrains Mono", "Fira Code", "Consolas", monospace;
                font-size: 11px;
            }

            /* ===== View ===== */
            #viewInfo {
                background: rgba(30, 60, 95, 0.3);
                border: 1px solid #2a4a70;
                border-radius: 6px;
                padding: 10px 14px;
                font-size: 12px;
                color: #8ec5f0;
            }

            #viewContent {
                background: #0d1117;
                color: #c8d0da;
                border: 1px solid #1e2733;
                border-radius: 6px;
                padding: 12px;
                font-family: "JetBrains Mono", "Fira Code", "Consolas", monospace;
                font-size: 12px;
                line-height: 1.5;
            }

            /* ===== Scrollbar ===== */
            QScrollBar:vertical {
                background: #0f1419;
                width: 8px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: #2a3545;
                border-radius: 4px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #3a4a60;
            }
            QScrollBar::add-line, QScrollBar::sub-line {
                height: 0px;
            }
            QScrollBar::add-page, QScrollBar::sub-page {
                background: none;
            }

            QScrollBar:horizontal {
                background: #0f1419;
                height: 8px;
                border: none;
            }
            QScrollBar::handle:horizontal {
                background: #2a3545;
                border-radius: 4px;
                min-width: 30px;
            }

            /* ===== Message Box ===== */
            QMessageBox {
                background: #151b23;
            }
            QMessageBox QLabel {
                color: #d0d7e1;
            }
            QMessageBox QPushButton {
                background: #1e3a5f;
                color: #8ec5f0;
                border: 1px solid #2a4a70;
                padding: 6px 20px;
                border-radius: 4px;
                min-width: 80px;
            }

            /* ===== File Dialog ===== */
            QFileDialog {
                background: #151b23;
            }

            /* ===== Tooltips ===== */
            QToolTip {
                background: #1e2838;
                color: #d0d7e1;
                border: 1px solid #3a4a60;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
            }

            /* ===== Change Password Dialog ===== */
            QDialog {
                background: #151b23;
                border: 1px solid #2a3a50;
                border-radius: 14px;
            }
            #dialogInput {
                background: rgba(10, 14, 20, 0.8);
                color: #e0e7f0;
                border: 1px solid #2a3a50;
                border-radius: 8px;
                padding: 10px 14px;
                font-size: 13px;
            }
            #dialogInput:focus {
                border-color: #4a80c0;
            }
        """)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("CAMELLIA File Manager")
    app.setOrganizationName("BTL-Driver")

    # Đặt style hints
    app.setStyle("Fusion")

    # Tùy chỉnh palette cho dark mode
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(15, 20, 25))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(208, 215, 225))
    palette.setColor(QPalette.ColorRole.Base, QColor(19, 25, 32))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(22, 29, 38))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(30, 40, 56))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(208, 215, 225))
    palette.setColor(QPalette.ColorRole.Text, QColor(208, 215, 225))
    palette.setColor(QPalette.ColorRole.Button, QColor(30, 37, 48))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(160, 176, 196))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 74, 112))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(224, 231, 240))
    app.setPalette(palette)

    window = CamelliaFileManager()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
