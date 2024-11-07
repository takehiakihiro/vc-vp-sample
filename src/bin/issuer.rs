use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use jsonwebtoken::{
    jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, OctetKeyPairParameters,
        OctetKeyPairType, PublicKeyUse,
    },
    Algorithm, EncodingKey, Header,
};
use pem::parse;
use rand::{
    seq::SliceRandom, // SliceRandomトレイトをインポート
    thread_rng,       // 乱数生成器をインポート
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sd_jwt_payload::{Disclosure, SdJwt, SdObjectEncoder, HEADER_TYP};
use serde_json::{json, Number, Value};
use std::{fs::File, io::Read};

fn main() -> Result<()> {
    const ISSUER_PRIVATE_KEY: &str = "issuer_private_key_ed25519.pem";
    const HOLDER_PRIVATE_KEY: &str = "holder_private_key_ed25519.pem";

    // ======================= Holder part =======================
    // PEMファイルから秘密鍵を読み込み、公開鍵を取り出す
    let priv_key = read_pem_file(HOLDER_PRIVATE_KEY)
        .map_err(|e| anyhow!("failed to read pem e={}", e.to_string()))?;
    println!("priv_key={:?}", priv_key);
    let key_pair = generate_key_pair(&priv_key)
        .map_err(|e| anyhow!("failed to generate key pair e={}", e.to_string()))?;
    // 公開鍵をJWK形式に変換
    let pubkey_jwk = public_key_to_jwk(&key_pair)
        .map_err(|e| anyhow!("failed to convert to jwk e={}", e.to_string()))?;
    println!("pubkey_jwk={:?}", pubkey_jwk);

    // ======================= Issuer part =======================
    let id = "takehi";
    let dummy = "dummy";

    let mut object = json!({
      "id": id,
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
        encoder.conceal("/id", None)?,
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
    let mut header = Header::new(Algorithm::EdDSA);
    let token_type = format!("vc+{}", HEADER_TYP);
    header.typ = Some(token_type);

    // Use the encoded object as a payload for the JWT.
    let mut payload = encoder.object()?.clone();
    payload.insert(
        "iss".to_string(),
        Value::String("emotionlink-issuer".to_string()),
    );
    payload.insert(String::from("aud"), Value::String("el-client".to_string()));

    let now = std::time::SystemTime::now();
    let val = Number::from(
        now.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    payload.insert("iat".to_string(), Value::Number(val));

    let expires_at = now + std::time::Duration::from_secs(7 * 24 * 60 * 60);
    let val = Number::from(
        expires_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    payload.insert("exp".to_string(), Value::Number(val));

    let private_key = std::fs::read(ISSUER_PRIVATE_KEY).unwrap();
    let encoding_key = EncodingKey::from_ed_pem(&private_key)?;
    println!("loaded signer's private key");
    let jwt = jsonwebtoken::encode(&header, &payload, &encoding_key)?;

    // Create an SD_JWT by collecting the disclosures and creating an `SdJwt` instance.
    let mut disclosures: Vec<String> = disclosures
        .into_iter()
        .map(|disclosure| disclosure.to_string())
        .collect();

    // 乱数生成器を取得
    let mut rng = thread_rng();
    // ベクタの中身をランダムに入れ替える
    disclosures.shuffle(&mut rng);

    // disclosures の配列の中身をランダムに並べ替える
    let sd_jwt: SdJwt = SdJwt::new(jwt, disclosures, None);
    let sd_jwt: String = sd_jwt.presentation();
    println!("VC={}", sd_jwt);
    std::fs::write("vc.jwt".to_string(), sd_jwt)?;

    Ok(())
}

///
fn read_pem_file(file_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let pem = parse(contents)?;
    Ok(pem.contents().to_vec())
}

///
fn generate_key_pair(
    secret_key_bytes: &[u8],
) -> Result<Ed25519KeyPair, Box<dyn std::error::Error>> {
    let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(secret_key_bytes)?;
    Ok(key_pair)
}

///
fn public_key_to_jwk(key_pair: &Ed25519KeyPair) -> Result<Value, Box<dyn std::error::Error>> {
    let public_key_bytes = key_pair.public_key().as_ref();
    let x = general_purpose::URL_SAFE_NO_PAD.encode(public_key_bytes);

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
