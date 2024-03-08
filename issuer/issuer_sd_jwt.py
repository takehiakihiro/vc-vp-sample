import json
import time
from sd_jwt import SDJWTCreator

# 秘密鍵の読み込み
with open("private_key.pem", "rb") as f:
    private_key = f.read()

# VCのペイロードを作成
payload = {
    "iss": "did:example:issuer",
    "sub": "did:example:subject",
    "iat": int(time.time()),
    "exp": int(time.time()) + 24 * 60 * 60,  # 1日後に期限切れ
    "vc": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://example.com/credentials/v1"
        ],
        "type": ["VerifiableCredential", "AccountCredential"],
        "credentialSubject": {
            "account_name": "example_account",
            "ip_addresses": ["192.168.0.1", "192.168.0.2"],
            "dns_addresses": ["example.com", "example.org"],
            "route_networks": ["10.0.0.0/8", "172.16.0.0/12"],
            "group_name": "example_group"
        }
    }
}

# SDスコープを設定
sd_scope = {
    "account_name": {},
    "ip_addresses": {},
    "dns_addresses": {},
    "route_networks": {},
    "group_name": {}
}

# SD-JWTを生成
sd_jwt_creator = SDJWTCreator(
    algorithm="EdDSA",
    hash_alg="sha-256",
    key=private_key,
    kid="did:example:issuer#key-1"
)

sd_jwt = sd_jwt_creator.encode(
    payload,
    sd_scope
)

print(sd_jwt)
