use std::{fs::File, io::Read};

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use jsonwebtoken::{
    jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, OctetKeyPairParameters,
        OctetKeyPairType, PublicKeyUse,
    },
    Algorithm, EncodingKey, Header,
};
use pem::parse;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

fn main() -> Result<()> {
    const HOLDER_PRIVATE_KEY: &str = "holder_private_key_ed25519.pem";

    // ======================= Holder part =======================
    // PEMファイルから秘密鍵を読み込み、公開鍵を取り出す
    let priv_key = read_pem_file(HOLDER_PRIVATE_KEY)?;
    println!("priv_key={:?}", priv_key);
    let key_pair = generate_key_pair(&priv_key)?;
    // 公開鍵をJWK形式に変換
    let pubkey_jwk = public_key_to_jwk(&key_pair)?;
    println!("pubkey_jwk={:?}", pubkey_jwk);

    // Create the JWT.
    // Creating JWTs is outside the scope of this library, josekit is used here as an example.
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("JWT".to_string());

    let mut object = json!({});

    let mut inner_jwk = serde_json::Map::new();
    inner_jwk.insert("jwk".to_string(), pubkey_jwk);
    let cnf = match serde_json::to_value(inner_jwk) {
        Ok(v) => v,
        _ => panic!("failed to add"),
    };
    if let Value::Object(ref mut map) = object {
        map.insert("cnf".to_string(), cnf);
    }
    let payload = object.as_object().unwrap();

    let priv_key = read_file(HOLDER_PRIVATE_KEY)?;
    let encoding_key = EncodingKey::from_ed_pem(&priv_key)?;
    println!("loaded signer's private key");
    let jwt = jsonwebtoken::encode(&header, &payload, &encoding_key)?;

    println!("JWK's JWT={}", jwt);

    Ok(())
}

///
fn read_file(file_path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut contents = vec![];
    file.read_to_end(&mut contents)?;
    Ok(contents.to_vec())
}

///
fn read_pem_file(file_path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let pem = parse(contents)?;
    Ok(pem.contents().to_vec())
}

///
fn generate_key_pair(secret_key_bytes: &[u8]) -> Result<Ed25519KeyPair> {
    let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(secret_key_bytes)?;
    Ok(key_pair)
}

///
fn public_key_to_jwk(key_pair: &Ed25519KeyPair) -> Result<Value> {
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
