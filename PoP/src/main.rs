use josekit::{
    jwk::{Jwk, JwkSet},
    jws::{EdDSA, JwsHeader, JwsSigner},
};
use serde_json::{json, Value};

fn main() {
    // PEM形式のED25519公開鍵
    let public_key_pem = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAiOWUgGVQYBq6WkCjp9Kc4LZ7pRxwHVIqLiStJI+EBUs=
-----END PUBLIC KEY-----"#;

    // PEM形式の公開鍵からJwkを作成
    let jwk = Jwk::from_bytes(public_key_pem).unwrap();

    // JwkSetを作成
    let jwk_set = JwkSet::new(vec![jwk]);

    // cnfクレームを作成
    let cnf_claim = json!({
        "jwk": jwk_set.to_public(),
    });

    // JWTのペイロードを作成
    let payload: Value = json!({
        "iss": "https://example.com",
        "sub": "user123",
        "cnf": cnf_claim,
    });

    // JWSヘッダーを作成
    let mut header = JwsHeader::new();
    header.set_algorithm(EdDSA);

    // JWTを署名
    let key = josekit::jwk::Jwk::generate(EdDSA).unwrap();
    let signer = JwsSigner::new(header, key.clone()).unwrap();
    let jwt = signer.sign(&payload.to_string()).unwrap();

    println!("JWT with cnf claim: {}", jwt);
}
