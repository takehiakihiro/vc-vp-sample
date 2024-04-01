# ELプロトコルの認証部分のRustでの実装について

## Issuer

### SD-JWT VC 生成

sd-jwt-payload を使うことで、key binding の cnf の部分以外のJWTの元のJSONは生成できる。
- Holderから受け取った JWK 形式の cnf を sd-jwt-payload で生成した JSON に追加。
- JSON から JWT 生成。

## Holder

Issuerの公開鍵は持っているか取りに行ける前提。

### Issuer に渡す公開鍵を JWK 形式に変換する

以下のコードで 秘密鍵の PEM から JWK 形式に変換できる。

```
use josekit::jwk::alg::ed::EdKeyPair;
    let private_pem_file_content = std::fs::read("issuer_private_key_ed25519.pem").unwrap();
    let key_pair = EdKeyPair::from_pem(private_pem_file_content).unwrap();
    let jwk = key_pair.to_jwk_public_key();
    println!("jwk={:?}", jwk.to_string());
```

### VC の Verify

- sd-jwt-payload を使うことで、Issuerの公開鍵でVerifyできる。この時 Disclosure の中身も確認できる。

### VPとして公開する disclosure を選択

VP として公開する Disclosure を選択する。

### Key binding JWT の生成

以下の項目を入力することで sd-jwt-payload の KeyBindingJwtClaims::new() から Key binding JWTのもとになる JSON を生成。(sd_hash以外は値を直接josekit::jwt::JwtPayload::new()で生成したオブジェクトに設定)
- SD-JWT VCのコアのJWTのBase64urlエンコード文字列
- 公開するDisclosureのVec<String> (Base64urlエンコードされた文字列のVec)
- nonce (ランダム？)
- audience (ELサーバのこと)
- iat (生成時間)

josekit を使って JSON をJWT形式に変換し、KB-JWTとする。

### VP 生成

SdJwt::new()
- SD-JWT VCのコアのJWTのBase64urlエンコード文字列
- 公開するDisclosureのVec<String> (Base64urlエンコードされた文字列のVec)
- Key binding JWTのBase64urlエンコードされた文字列

## Verifier

Issuerの公開鍵は持っているか取りに行ける前提。

### VP を以下の３つの部分に分ける

- VC のコア部分の JWT
- Disclosure のBase64urlエンコードされた文字列のリスト
- KB-JWT

### Holder の公開鍵を取り出す

- sd-jwt-payload を使い、VC のコア部分の JWT と Disclosure のリストを、VerifyしながらJSON形式に変換する。
- cnf キー以下の Holder の公開鍵を取り出し、使える形にする（TODO: ここは josekit::jwk を使えばできるか？）

### KB-JWT の Verify

Holder の公開鍵と josekit::jwt を使い、KB-JWT の Verify を行い、aud/iat/sd_hash を取り出す。

### KB-JWT の中身の確認

- aud の確認
- iat の期限切れの確認
- sd_hash が VC のコア部分と Disclosure のリストの部分のハッシュと一致するかを確認

### すべての確認が完了したので VC の中身を取り出す

既に Disclosure のリストは Verify 時に JSON に変換済みなので、そこからデータを取り出す。なので VC には以下の項目が必要
- account_name
- group_name
- ip_addresses
- route_networks
- dns_addresses (optional)
