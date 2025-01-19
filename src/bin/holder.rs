use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use sd_jwt_payload::{KeyBindingJwtClaims, SdJwt, Sha256Hasher};
use serde::{Deserialize, Serialize};
use serde_json::{json, Number, Value};
use std::{error::Error, fs::File, io::Read};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    _sd: Vec<String>,
    aud: String,
    iss: String,
    iat: i64,
    exp: i64,
}

fn main() -> Result<(), Box<dyn Error>> {
    // 秘密鍵をファイルから読み込み
    #[cfg(feature = "EdDSA")]
    const ISSUER_PUBLIC_KEY: &str = "issuer_public_key_ed25519.pem";
    #[cfg(feature = "ES256")]
    const ISSUER_PUBLIC_KEY: &str = "issuer_public_key_ES256.pem";
    #[cfg(feature = "EdDSA")]
    const HOLDER_PRIVATE_KEY: &str = "holder_private_key_ed25519.pem";
    #[cfg(feature = "ES256")]
    const HOLDER_PRIVATE_KEY: &str = "holder_private_key_ES256_pkcs8.pem";

    let vc = std::fs::read_to_string("vc.jwt").unwrap();

    let sd_jwt: SdJwt = SdJwt::parse(&vc)?;
    println!("sd_jwt: {:?}", sd_jwt);

    let public_key = read_pem_file(ISSUER_PUBLIC_KEY)?;
    println!("public_key: {:?}", public_key);
    #[cfg(feature = "EdDSA")]
    let decoding_key = DecodingKey::from_ed_pem(&public_key)?;
    #[cfg(feature = "ES256")]
    let decoding_key = DecodingKey::from_ec_pem(&public_key)?;
    println!("decoding_key");
    #[cfg(feature = "EdDSA")]
    let mut validation = Validation::new(Algorithm::EdDSA);
    #[cfg(feature = "ES256")]
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["fujita-app"]);
    let token_data = jsonwebtoken::decode::<Value>(&sd_jwt.jwt, &decoding_key, &validation)?;
    println!("sd-jwt's header={:?}", token_data.header);
    println!("sd-jwt's payload={:?}", token_data.claims);
    println!();

    // disclosures の中から、公開したいものを Base64url decode して中身を見て選別する
    let mut disclosures = Vec::new();

    for encoded_str in sd_jwt.disclosures {
        let mut buffer = Vec::<u8>::new();
        let check_strings = ["id"];

        // Base64urlデコードを試みる
        if URL_SAFE_NO_PAD
            .decode_vec(encoded_str.as_bytes(), &mut buffer)
            .is_ok()
        {
            // デコードされた文字列を取得
            if let Ok(decoded_str) = String::from_utf8(buffer) {
                // JSONとしてパース
                if let Ok(json) = serde_json::from_str::<Value>(&decoded_str) {
                    println!("checking decoded={:?}, encoded={}", json, encoded_str);
                    // JSONが配列形式であり、2番目の要素が指定した文字列のいずれかに一致するかチェック
                    if json.as_array().is_some_and(|arr| {
                        arr.get(1).is_some_and(|second_element| {
                            check_strings.contains(&second_element.as_str().unwrap_or(""))
                        })
                    }) {
                        // 条件を満たす場合、元のBase64urlエンコードされた文字列を保存
                        println!("MATCH! decoded={:?}, encoded={}", json, encoded_str);
                        disclosures.push(encoded_str.to_string());
                    }
                }
            }
        }
    }
    let nonce = "nonce".to_string();
    let audience = "el-server".to_string();
    let hasher = Sha256Hasher::new();
    let key_binding_jwt = KeyBindingJwtClaims::new(
        &hasher,
        sd_jwt.jwt.clone(),
        disclosures.clone(),
        nonce,
        audience,
        0,
    );

    #[cfg(feature = "EdDSA")]
    let mut header = Header::new(Algorithm::EdDSA);
    #[cfg(feature = "ES256")]
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("kb+jwt".to_string());

    let binding = json!({});
    let mut payload = binding.as_object().unwrap().clone();

    payload.insert("nonce".to_string(), Value::String(key_binding_jwt.nonce));
    payload.insert(
        "sd_hash".to_string(),
        Value::String(key_binding_jwt.sd_hash),
    );
    payload.insert(
        String::from("aud"),
        Value::String(key_binding_jwt.aud.clone()),
    );

    let now = std::time::SystemTime::now();
    let val = Number::from(
        now.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    payload.insert("iat".to_string(), Value::Number(val));

    let expires_at = now + std::time::Duration::from_secs(60);
    let val = Number::from(
        expires_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    payload.insert("exp".to_string(), Value::Number(val));

    let holder_private_key = std::fs::read(HOLDER_PRIVATE_KEY).unwrap();
    #[cfg(feature = "EdDSA")]
    let encoding_key = EncodingKey::from_ed_pem(&holder_private_key)?;
    #[cfg(feature = "ES256")]
    let encoding_key = EncodingKey::from_ec_pem(&holder_private_key)?;
    println!("loaded signer's private key");
    let key_binding_jwt = jsonwebtoken::encode(&header, &payload, &encoding_key)?;
    println!("kb-jwt: {:?}", key_binding_jwt);
    println!();

    let sd_jwt: SdJwt = SdJwt::new(sd_jwt.jwt, disclosures.clone(), Some(key_binding_jwt));
    let sd_jwt: String = sd_jwt.presentation();

    println!("VP={:?}", sd_jwt);
    std::fs::write("vp.jwt", sd_jwt)?;

    Ok(())
}

/// PEMファイルから読み取り
fn read_pem_file(file_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = vec![];
    file.read_to_end(&mut contents)?;
    // let pem = parse(contents)?;
    // Ok(pem.contents().to_vec())
    Ok(contents)
}
