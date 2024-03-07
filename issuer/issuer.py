from jose import jwt
from jose.utils import base64url_encode
import datetime
import json

# Issuerの秘密鍵（例としてここに直接記述しますが、実際には安全に管理する必要があります）
private_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDzXwabY+CujqjL
9ajbRR14JFzMF2SC+1jlHyZVdqZ6jxtuywvmniioxFLbrWN32OiYQI30IFX/QLFn
c6jk7Wt1SU3ObYCDH4KhjV2pqOx2b08WPmwgp1ecTE1Z9MSPsuD+nKmPshMizk/w
28MJIDT35iHcXpC/AD3JJyY7D1uldEsxFAsxANE1DPumAD3nmMCO4qHWvkCEK1bM
TEZwhHPjv45TXYLhc0+1uhIWbs6DWSlJvdF7oNplAgOXb4LwxsHyPB9A2yiXuf7m
WR0+XMYruXDwvbj2nT6G+LFIPYNUm06GDg5oRVtmnhlyPTiJynU/9Lf8j7hKo9Pz
C2Jpe711AgMBAAECggEAF46iLWu3NY5PiSE9TVmHpw0grQyynk8aurWPg1mZzGaK
dD3+kpMf7RNxJccccrRcnKgwVWoaiOZH2x4B7NmNEOxIi2u5Xc0wsCyRMrlMMjvx
/tLfVTB9itPZROosFfDDAJeaKMjxkJPsfwGhWQJ0vhjY5uOBxUs5BSiJ9dDga8er
+759Nl8DynDJ1uVJcpu/Of5EbwtrScB7Ch0aqvAebS7q/2l0EWvySJrEH74m77JQ
7fB8WofRadm2wl38eGq1fKcUuKY8Moo7JzkdIK6v9DvAYpPLNN3KJAEkqbUa29oi
sIznOvpW1K5q0T4gBpSC5Qw1zSzDKKEluvdRSapa3QKBgQD4z4e8ovu79KKWZyQa
uUqTcJ3+tMS0f7yMAMBr/HvjHRk/5OGgSXanEpJnuAVpBjUjTOtcVziPjWTeQqk3
zZcFBC/2WG5PxoYGcBmSf2PEOQtYr0ziOfB6PTGxLs58WAlBEToFuD0y/+85+MH6
+1p6XecYkOBNn7OmUNEPWKOxNwKBgQD6Z0JrEIvc5bo/RUVzXvPT3O0yeawvn7cr
whV8o57w9Qfgwnw6nQtRz5/XQAo9BMcgmSemKOFArDMwVNaynmyOpCyvOI8Web/a
peIsOpaRq2XSDRs2upcKutPmjA1HDxgCj0cAVsGxH6zBHT7DmfUUSMQ1kRyy1Xy1
HXGdRCnMswKBgQCBbCIlI3pieIwiRCBprjx2mTv2A73WTiObh8CP61Pd/YLm033x
zITlvylcvkJCMTJu3FIJRG1tbpUrb+1p041c1KLGN5WZ9aA9tQ34QD97EFkwlm8d
thm63B3/FmPeFkUqDXXrB7z9zFd6BkWQ8jJMOJA/HQ0wE4R1XNCCdQ8g3QKBgE4c
wB9d/gNetobeORgQWseQd33zbr88d4ty8/j5oa9RALAge1hdfRZ8SkR/ebInN2b3
3+J5hisCjMVa8c6ulPa6SCYw4pIEUNEIRlG9xRKUASNRa1fbRRrXxRp6PfoYv0it
IVz9s1Zppx5m3RlvgYBeYrbDGcy/xDNLiBGjHdb5AoGAc3MsUKgoPQl+LN/3kJHU
im4T1xNgQe2qc+xm8R6MEEJa5Hstj24zpVGQDe4DIbEJBPhCV2r7h3tKQzi5pv7z
iF1hsybDGzbss0lpmqmpj9Y8Mx6yuVBKYYy8A7dCBl3OYG1H8DFXptNA9KLU+tn2
gOLVu5WwKi57srmMrNScK58=
-----END PRIVATE KEY-----"""

# VCのペイロード
payload = {
    "sub": "1234567890", # 患者ID
    "address": "1234 Main St", # 住所
    "iss": "VCVPSampleIssuer", # Issuerを識別するための情報
    "iat": int(datetime.datetime.now().timestamp()), # 発行日時
}

# VCを署名して生成
encoded_jwt = jwt.encode(payload, private_key, algorithm='RS256')

print(encoded_jwt)