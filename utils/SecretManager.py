import botocore
import botocore.session
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig
import logging
import json


class SecretManager:
    def __init__(self):
        client = botocore.session.get_session().create_client('secretsmanager')
        cache_config = SecretCacheConfig() # See below for defaults
        self.cache = SecretCache(config=cache_config, client=client)

    def get_secret(self, key):
        return json.loads(self.cache.get_secret_string(key))
        
if __name__ == '__main__':
    try:
        print(SecretManager().get_secret("BLACKDUCK_SERVER_URL")["BLACKDUCK_SERVER_URL"])
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
