use anyhow::{anyhow, Result};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::{rng, seq::SliceRandom};
#[cfg(feature = "EdDSA")]
use ring::signature::{Ed25519KeyPair, KeyPair};
use sd_jwt_payload::{Disclosure, SdJwt, SdObjectEncoder, HEADER_TYP};
use serde_json::{json, Number, Value};
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // 第一引数が存在するか確認
    let account_name = match args.get(1) {
        Some(v) => v.to_string(),
        None => "takehi".to_string(),
    };

    let expires_days = match args.get(2) {
        Some(v) => v.parse()?,
        None => 7,
    };

    #[cfg(feature = "EdDSA")]
    const ISSUER_PRIVATE_KEY: &str = "issuer_private_key_ed25519.pem";
    #[cfg(feature = "ES256")]
    const ISSUER_PRIVATE_KEY: &str = "issuer_private_key_ES256_pkcs8.pem";
    #[cfg(feature = "EdDSA")]
    const HOLDER_KEY: &str = "holder_private_key_ed25519.pem";
    #[cfg(feature = "ES256")]
    const HOLDER_KEY: &str = "holder_public_key_ES256.pem";

    // ======================= Holder part =======================
    // PEMファイルから秘密鍵を読み込み、公開鍵を取り出す
    let pubkey_jwk = public_key_to_jwk(HOLDER_KEY)
        .map_err(|e| anyhow!("failed to convert to jwk e={}", e.to_string()))?;
    println!("pubkey_jwk={pubkey_jwk}");

    // ======================= Issuer part =======================
    let id = &account_name;
    let dummy = "dummy";

    let mut object = json!({
      "did": id,
      "dummy": dummy,
    });

    let mut inner_jwk = serde_json::Map::new();
    inner_jwk.insert("jwk".to_string(), pubkey_jwk);
    let cnf = match serde_json::to_value(inner_jwk) {
        Ok(v) => v,
        _ => panic!("failed to add"),
    };
    if let Value::Object(ref mut map) = object {
        map.insert("cnf".to_string(), cnf);
    }

    let mut encoder: SdObjectEncoder = object.try_into()?;
    let disclosures: Vec<Disclosure> = vec![
        encoder.conceal("/did", None)?,
        encoder.conceal("/dummy", None)?,
    ];

    encoder.add_decoys("", 2)?; // Add decoys to the top level.

    // encoder.add_sd_alg_property();

    println!(
        "encoded object: {}",
        serde_json::to_string_pretty(encoder.object()?)?
    );

    // Create the JWT.
    // Creating JWTs is outside the scope of this library, josekit is used here as an example.
    #[cfg(feature = "EdDSA")]
    let mut header = Header::new(Algorithm::EdDSA);
    #[cfg(feature = "ES256")]
    let mut header = Header::new(Algorithm::ES256);
    let token_type = format!("vc+{HEADER_TYP}");
    header.typ = Some(token_type);

    // Use the encoded object as a payload for the JWT.
    let mut payload = encoder.object()?.clone();
    payload.insert(
        "iss".to_string(),
        Value::String("emotionlink-issuer".to_string()),
    );
    payload.insert(String::from("aud"), Value::String("fujita-app".to_string()));

    let now = std::time::SystemTime::now();
    let val = Number::from(
        now.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    payload.insert("iat".to_string(), Value::Number(val));

    let expires_at = now + std::time::Duration::from_secs(expires_days * 24 * 60 * 60);
    let val = Number::from(
        expires_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    payload.insert("exp".to_string(), Value::Number(val));

    let private_key = std::fs::read(ISSUER_PRIVATE_KEY).unwrap();
    #[cfg(feature = "EdDSA")]
    let encoding_key = EncodingKey::from_ed_pem(&private_key)?;
    #[cfg(feature = "ES256")]
    let encoding_key = EncodingKey::from_ec_pem(&private_key)?;
    println!("loaded signer's private key");
    let jwt = jsonwebtoken::encode(&header, &payload, &encoding_key)?;

    // Create an SD_JWT by collecting the disclosures and creating an `SdJwt` instance.
    let mut disclosures: Vec<String> = disclosures
        .into_iter()
        .map(|disclosure| disclosure.to_string())
        .collect();

    // 乱数生成器を取得
    let mut rng = rng();
    // ベクタの中身をランダムに入れ替える
    disclosures.shuffle(&mut rng);

    // disclosures の配列の中身をランダムに並べ替える
    let sd_jwt: SdJwt = SdJwt::new(jwt, disclosures, None);
    let sd_jwt: String = sd_jwt.presentation();
    println!("VC={sd_jwt}");
    std::fs::write("vc.jwt", sd_jwt)?;

    Ok(())
}

/// PEMファイルから鍵を取り出す
#[cfg(feature = "EdDSA")]
fn read_pem_file(file_path: &str) -> Result<Vec<u8>> {
    use pem::parse;
    let pem = parse(std::fs::read(file_path)?)?;
    Ok(pem.contents().to_vec())
}

/// キーペアを生成
#[cfg(feature = "EdDSA")]
fn generate_key_pair(file_path: &str) -> Result<Ed25519KeyPair> {
    let secret_key_bytes = read_pem_file(file_path)?;
    let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&secret_key_bytes)?;
    Ok(key_pair)
}

/// 公開鍵をJWK形式に変換する
#[cfg(feature = "EdDSA")]
fn public_key_to_jwk(file_path: &str) -> Result<Value, Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, OctetKeyPairParameters,
        OctetKeyPairType, PublicKeyUse,
    };

    let key_pair = generate_key_pair(file_path)?;

    let public_key_bytes = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(public_key_bytes);

    let common = CommonParameters {
        public_key_use: Some(PublicKeyUse::Signature),
        key_operations: None,
        key_algorithm: None,
        key_id: None,
        x509_url: None,
        x509_chain: None,
        x509_sha1_fingerprint: None,
        x509_sha256_fingerprint: None,
    };

    let params = OctetKeyPairParameters {
        key_type: OctetKeyPairType::OctetKeyPair,
        curve: EllipticCurve::Ed25519,
        x,
    };
    let algorithm = AlgorithmParameters::OctetKeyPair(params);

    let jwk = Jwk { common, algorithm };

    let jwk_value = serde_json::to_value(&jwk)?;
    Ok(jwk_value)
}

#[cfg(feature = "ES256")]
fn public_key_to_jwk(file_path: &str) -> Result<Value> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::{elliptic_curve::sec1::ToEncodedPoint as _, pkcs8::DecodePublicKey};

    let secret_key = std::fs::read_to_string(file_path)?;
    let public_key = p256::PublicKey::from_public_key_pem(&secret_key).inspect_err(|&e| {
        eprintln!("failed convert public key from pem e={e:?}");
    })?;
    // 座標を取り出す (圧縮なしのポイントにする: to_encoded_point(false))
    let encoded_point = public_key.to_encoded_point(false);
    let x_bytes = encoded_point
        .x()
        .ok_or("Failed to get X coordinate")
        .map_err(|e| {
            eprintln!("failed get x from pubkey e={e:?}");
            anyhow!(e)
        })?;
    let y_bytes = encoded_point
        .y()
        .ok_or("Failed to get Y coordinate")
        .map_err(|e| {
            eprintln!("failed get y from pubkey e={e:?}");
            anyhow!(e)
        })?;

    // ---- (3) x, y を Base64URL (padding なし) でエンコード
    let x = URL_SAFE_NO_PAD.encode(x_bytes);
    let y = URL_SAFE_NO_PAD.encode(y_bytes);

    // ---- (4) 必要なフィールドを揃えて JWK (公開鍵) を生成
    // ES256(P-256) の JWK には "kty", "crv", "x", "y" が必須となります
    // "alg" や "kid", "use", "key_ops" 等は必要に応じて追加してください
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "alg": "ES256",
        "use": "sig", // 署名用途の場合は例えばこう指定
        // "kid": "任意のキーID",
        // "key_ops": ["verify"], など
    });

    Ok(jwk)
}
