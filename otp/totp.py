import base64
import hmac
import hashlib
import struct
import os
import io
from time import time
from typing import Optional

import yaml
import qrcode

from redis_cli import RedisInit


class OTPError(Exception):
    def __init__(self, msg: Optional[str] = "otp error"):
        super().__init__(f"error: {msg}")


class TOTP:
    def __init__(self):
        """
        Initialize TOTP
        """
        self._interval = None
        self._digits = None
        self._secret_length = None
        self._attempts_before_ban = None
        self._ban_time = None
        self._period = None
        self._period_attempts = None
        self.update_config()

        self._redis_init = RedisInit('auth')
        self._redis_cl = self._redis_init.get_client()

    def update_config(self):
        with open('config/otp_config.yaml', 'r') as f:
            _config = yaml.safe_load(f)
        self._interval = _config['totp']['totp_interval']
        self._digits = _config['totp']['digits']
        self._secret_length = _config['totp']['secret_bytes_length']
        self._attempts_before_ban = _config['totp']['attempts_before_ban']
        self._ban_time = _config['totp']['ban_time']
        self._period = _config['totp']['period']
        self._period_attempts = _config['totp']['period_attempts']

    def generate_secret(self):
        """
        Generate a unique Base32 secret for a user.
        :return: Base32-encoded secret
        """
        return base64.b32encode(os.urandom(self._secret_length)).decode('utf-8')

    def _time_counter(self, timestamp=None):
        """
        Get the current time step.
        :param timestamp: Optional custom timestamp (for testing)
        :return: Current time step value
        """
        if timestamp is None:
            timestamp = time()
        return int(timestamp // self._interval)

    def _get_totp_token(self, secret):
        """
        Generate a TOTP using HMAC-SHA256.
        :param secret: Base32 secret key
        :return: OTP code
        """
        key = base64.b32decode(secret)
        counter = self._time_counter()  # In TOTP, we use time, not a counter
        counter_bytes = struct.pack(">Q", counter)

        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha256).digest()

        offset = hmac_hash[-1] & 0x0F
        binary_code = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF

        return str(binary_code % (10 ** self._digits)).zfill(self._digits)

    def generate_qr(self, secret: str, login: str, issuer: str):
        """
        Generate a QR code for the TOTP secret.
        :param secret: Base32 secret key
        :param login: User login/phone/mail from db
        :param issuer: App name (shown in authenticator)
        :return: QR code as bytes
        !!!!!!!!!!!! FIRST GENERATE SECRET AND INSERT INTO USER DB!!!!!!!!!
        """
        uri = f"otpauth://totp/{issuer}:{login}?secret={secret}&issuer={issuer}&digits={self._digits}&period={self._interval}"

        qr = qrcode.make(uri)

        img_io = io.BytesIO()
        qr.save(img_io, format="PNG")
        img_io.seek(0)

        return img_io.getvalue()

    def _check_ban(self, _key):
        attempts = self._redis_cl.get(name=f"{_key}_ban")
        if attempts is None:
            self._redis_cl.set(name=f"{_key}_ban",
                               value=str(self._attempts_before_ban - 1),
                               ex=self._ban_time)
            return
        try:
            _attempts = int(attempts)
        except ValueError:
            _attempts = 0

        if _attempts <= 0:
            raise OTPError("temporary banned")

        self._redis_cl.set(name=f"{_key}_ban",
                           value=_attempts - 1,
                           ex=self._ban_time)

    def check_periodically(self, _key):
        _cache_data = self._redis_cl.get(name=f"{_key}_periodic")
        if _cache_data is None:
            self._redis_cl.set(name=f"{_key}_periodic",
                               value=f"{str(self._period_attempts - 1)}_{int(time() * 1000)}",
                               ex=self._period)
            return
        try:
            _attempts, _created_at = map(int, _cache_data.split('_'))
        except ValueError:
            _attempts = 0
            _created_at = int(time() * 1000)

        if _attempts <= 0:
            raise OTPError(f"you were temporary banned for {self._period}")

        _new_ex = max(self._period - (int(time() * 1000) - _created_at) + 1, 1)

        self._redis_cl.set(name=f"{_key}_periodic",
                           value=f"{_attempts - 1}_{int(time() * 1000)}",
                           ex=_new_ex)

    def verify_otp(self,
                   user: str,
                   secret: str,
                   otp: str,
                   tolerance=1):
        print(user, secret, otp)
        """
        Verify user-provided OTP.
        :param user: any user identifier
        :param secret: Base32 secret key
        :param otp: User-entered OTP
        :param tolerance: Allowed time drift (default: 1)
        :return: True if valid, False otherwise
        """
        self._check_ban(f"{user}_totp")
        self.check_periodically(f"{user}_totp")
        current_counter = self._time_counter()
        """
        Check current and neighboring time steps
        """
        for offset in range(-tolerance, tolerance + 1):
            print(self._get_totp_token(secret))
            if otp == self._get_totp_token(secret):
                return True

        raise OTPError()


totp = TOTP()
