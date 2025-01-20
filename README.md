# vc-vp-sample

## ES256

秘密鍵は `pkcs8_private_key.pem` を使わないと読み込んでもらえない。
公開鍵は `public_key.pem` のまま使える。

```
openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
openssl pkcs8 -topk8 -nocrypt -in private_key.pem -out pkcs8_private_key.pem
```
