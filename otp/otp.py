import secrets
from time import time
from string import digits
from typing import Optional

import yaml
from redis_cli import RedisInit


class OTPError(Exception):
    def __init__(self, msg: Optional[str] = "otp error"):
        super().__init__(f"error: {msg}")


class OTP:
    def __init__(self, instance):
        """
        :param instance: otp instance: reg otp, auth, restore etc.
        """
        self._code_lifetime = None
        self._code_length = None
        self._check_attempts = None
        """
        After int(req_before_ban) code requests
        Phone/Mail should be banned for otp
        For self._reg_ban_time seconds
        """
        self._attempts_before_ban = None
        self._code_ban_time = None

        self._period = None
        self._period_attempts = None
        self.update_config(instance)

        self._redis_init = RedisInit('reg')
        self._redis_cl = self._redis_init.get_client()

    def update_config(self, _instance):
        with open("otp_config.yaml", 'r') as _f:
            _config = yaml.safe_load(_f)
            config = _config[_instance]

        self._code_lifetime = config['code_lifetime']
        self._code_length = config['code_length']
        self._check_attempts = config['check_attempts']
        """
        After int(req_before_ban) code requests
        Phone/Mail should be banned for otp
        For self._reg_ban_time seconds
        """
        self._attempts_before_ban = config['attempts_before_ban']
        self._code_ban_time = config['code_ban_time']

        """"
        {_period_attempts} requests per _period hours
        """
        self._period = config['period'] * 24
        self._period_attempts = config['period_attempts']

    def _check_ban(self, _key):
        """
        It is a procedure
        When phone/mail request the reg code too frequently
        - this phone/mail is banned for self._reg_ban_time seconds
        :param _key:
        :return: nothing or RegistrationError
        """
        attempts = self._redis_cl.get(name=f"{_key}_ban")
        if attempts is None:
            self._redis_cl.set(name=f"{_key}_ban",
                               value=str(self._attempts_before_ban - 1),
                               ex=self._code_ban_time)
            return
        try:
            _attempts = int(attempts)
        except ValueError:
            _attempts = 0

        if _attempts <= 0:
            raise OTPError("temporary banned")

        self._redis_cl.set(name=f"{_key}_ban",
                            value=_attempts - 1,
                            ex=self._code_ban_time)

    def _check_periodically(self, _key):
        """
        This is a procedure for limiting the number of OTP requests
        over a longer period of time, such as 15 requests per day.
        :param _key:
        :return:
        """
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

    def create_code(self, _key: str) -> str:
        """
        Universal method to create code in redis
        Use with context added into _key (_reg _auth _restore etc.)
        :param _key: phone or email
        :return: code or RegistrationError
        EXAMPLE: _key = user1_auth
        """
        self._check_ban(_key)
        self._check_periodically(_key)

        _cache_data = self._redis_cl.get(name=_key)
        if _cache_data is not None:
            raise OTPError("code already required")

        _code = ''.join(secrets.choice(digits)
                        for _ in range(self._code_length))

        self._redis_cl.set(
            name=_key,
            value=f"{_code}_{self._check_attempts}_{int(time())}",
            ex=self._code_lifetime)

        return _code

    def verify_code(self, _key: str, received_code: str) -> bool:
        """
        :param _key:
        :param received_code:
        :return: True or Exception
        EXAMPLE: _key = user1_auth
        """
        _cache_data = self._redis_cl.get(name=_key)
        if _cache_data is None:
            raise OTPError("you need to require a code")

        _code_data = str(_cache_data).split("_")
        _code = _code_data[0]
        _attempts = int(_code_data[1])
        _created_at = int(_code_data[2])

        if _attempts <= 0:
            raise OTPError("no attempts left")

        if _code == received_code:
            """
            delete otp from redis and ban
            because user should not auth twice
            """
            self._redis_cl.delete(_key)
            self._redis_cl.get(name=f"{_key}_ban")
            return True

        _new_ex = self._code_lifetime - (int(time()) - _created_at) + 1
        self._redis_cl.set(
            name=_key,
            value=f"{_code}_{_attempts - 1}_{int(time())}",
            ex=_new_ex)

        raise OTPError("code wrong")

