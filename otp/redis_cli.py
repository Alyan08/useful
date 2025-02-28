import os

import yaml
import redis


class RedisInit:
    def __init__(self, instance):
        self._redis_config = self._load_config(instance)
        self._redis_client = self._connect_to_redis()

    def _load_config(self, _instance):
        with open("config/redis_config.yaml", 'r') as _f:
            config = yaml.safe_load(_f)
        return config[_instance]

    def _connect_to_redis(self):
        host = self._redis_config['host']
        port = self._redis_config['port']
        db = self._redis_config['db']
        redis_pwd = None
        if self._redis_config['need_password']:
            password_location = self._redis_config['password_location']
            if password_location == "config":
                redis_pwd = self._redis_config['password']
            if password_location == "env":
                redis_pwd = os.getenv('mfa_redis_pwd')

        client = redis.StrictRedis(host=host, port=port,
                                   db=db, password=redis_pwd,
                                   decode_responses=True)

        try:
            client.ping()
        except redis.ConnectionError:
            raise

        return client

    def get_client(self):
        return self._redis_client

