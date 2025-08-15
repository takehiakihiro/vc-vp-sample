use anyhow::{anyhow, Result};
use base64::Engine;
use josekit::{
    jwk::Jwk,
    jws::{JwsHeader, ES256},
    jwt::{self, JwtPayload},
};
use rand::{
    seq::SliceRandom, // SliceRandomトレイトをインポート
};
#[cfg(feature = "EdDSA")]
use ring::signature::{Ed25519KeyPair, KeyPair};
use sd_jwt_payload::{Disclosure, SdJwt, SdObjectEncoder};
use serde_json::{json, Value};
use std::env;

struct GenerateVCParams {
    pub issuer: String,
    pub vct: String,
    pub private_key: Vec<u8>,
    pub jwk: Jwk,
    pub account_name: String,
    pub ip_address: String,
    pub route_networks: Vec<String>,
    pub dns_addresses: Vec<String>,
    pub group_name: String,
    pub vc_expires_in: u64,
}

/// SD-JWT形式のVCを生成
fn generate_sd_jwt_vc(params: GenerateVCParams) -> anyhow::Result<String> {
    // This function should generate a real SD-JWT formatted VC
    // ======================= Issuer part =======================
    let ip_addresses = [params.ip_address];

    let mut object = serde_json::json!({
      "account_name": params.account_name,
      "ip_addresses": ip_addresses,
      "dns_addresses": params.dns_addresses,
      "route_networks": params.route_networks,
      "group_name": params.group_name,
    });

    let mut inner_jwk = serde_json::Map::new();
    let jwk_obj = serde_json::from_str(&params.jwk.to_string())
        .map_err(|e| anyhow!("failed to convert serde Value from JWK: {}", e.to_string()))?;
    inner_jwk.insert("jwk".to_string(), jwk_obj);
    let cnf = serde_json::to_value(inner_jwk)
        .map_err(|e| anyhow!("failed to add JWK to serde object: {}", e.to_string()))?;

    if let Value::Object(ref mut map) = object {
        map.insert("cnf".to_string(), cnf);
    }

    let mut encoder: SdObjectEncoder = object.try_into()?;
    let disclosures: Vec<Disclosure> = vec![
        encoder.conceal("/account_name", None)?,
        encoder.conceal("/ip_addresses", None)?,
        encoder.conceal("/dns_addresses", None)?,
        encoder.conceal("/route_networks", None)?,
        encoder.conceal("/group_name", None)?,
    ];

    encoder.add_decoys("", 2)?; // Add decoys to the top level.

    // Create the JWT.
    // Creating JWTs is outside the scope of this library, josekit is used here as an example.
    let mut header = JwsHeader::new();
    let token_type = format!("vc+{}", sd_jwt_payload::HEADER_TYP);
    header.set_token_type(token_type);
    #[cfg(feature = "EdDSA")]
    header.set_algorithm("EdDSA"); // EdDSA署名アルゴリズムの指定
    #[cfg(feature = "ES256")]
    header.set_algorithm("ES256"); // EdDSA署名アルゴリズムの指定

    // Use the encoded object as a payload for the JWT.
    let mut payload = JwtPayload::from_map(encoder.object()?.clone())?;
    payload.set_issuer(params.issuer);
    let _ = payload.set_claim("vct", Some(Value::from(params.vct)));
    let audiences = vec!["el-client".to_string()];
    payload.set_audience(audiences);
    let now = std::time::SystemTime::now();
    let expires_at = now + std::time::Duration::from_secs(params.vc_expires_in);
    payload.set_issued_at(&now);
    payload.set_expires_at(&expires_at);

    #[cfg(feature = "EdDSA")]
    let signer = EdDSA
        .signer_from_pem(params.private_key)
        .map_err(|e| anyhow!("failed to convert signer from pem: {}", e.to_string()))?;
    #[cfg(feature = "ES256")]
    let signer = ES256
        .signer_from_pem(params.private_key)
        .map_err(|e| anyhow!("failed to convert signer from pem: {}", e.to_string()))?;

    println!("loaded signer's private key");
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)
        .map_err(|e| anyhow!("failed to encode with signer: {}", e.to_string()))?;

    // Create an SD_JWT by collecting the disclosures and creating an `SdJwt` instance.
    let mut disclosures: Vec<String> = disclosures
        .into_iter()
        .map(|disclosure| disclosure.to_string())
        .collect();

    // 乱数生成器を取得
    let mut rng = rand::rng();
    // ベクタの中身をランダムに入れ替える
    disclosures.shuffle(&mut rng);

    // disclosures の配列の中身をランダムに並べ替える
    let sd_jwt: SdJwt = SdJwt::new(jwt, disclosures, None);
    Ok(sd_jwt.presentation())
}

fn main() -> Result<()> {
    let issuer = env::var("ISSUER")
        .unwrap_or_else(|_e| "https://fujita-el-issuer.emotionlink.jp".to_string());
    let vct = env::var("VCT")
        .unwrap_or_else(|_e| "https://credentials.emotionlink.jp/fujitaapp_credential".to_string());

    #[cfg(feature = "EdDSA")]
    const ISSUER_KEY: &str = "el_issuer_private_key_ed25519.pem";
    #[cfg(feature = "ES256")]
    const ISSUER_KEY: &str = "el_issuer_private_key_ES256.pem";

    let private_key = std::fs::read_to_string(ISSUER_KEY).expect("Failed to read private key file");

    let route_network_addresses =
        env::var("ROUTE_NETWORK_ADDRESSES").expect("ROUTE_NETWORK_ADDRESSES must be set");
    let route_network_addresses = parse_split_string(&route_network_addresses);
    let dns_addresses = env::var("DNS_ADDRESSES").unwrap_or_else(|_| String::new());
    let dns_addresses = parse_split_string(&dns_addresses);
    let group = env::var("GROUP").expect("GROUP must be set");

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
    let vc_expires_in = expires_days * 24 * 60 * 60;

    let ip_address = match args.get(3) {
        Some(v) => v.to_string(),
        None => "10.0.0.100".to_string(),
    };

    #[cfg(feature = "EdDSA")]
    const HOLDER_KEY: &str = "el_holder_private_key_ed25519.pem";
    #[cfg(feature = "ES256")]
    const HOLDER_KEY: &str = "el_holder_public_key_ES256.pem";

    // ======================= Holder part =======================
    // PEMファイルから秘密鍵を読み込み、公開鍵を取り出す
    let pubkey_jwk = public_key_to_jwk(HOLDER_KEY)
        .map_err(|e| anyhow!("failed to convert to jwk e={}", e.to_string()))?;
    println!("pubkey_jwk={pubkey_jwk}");
    let jwk = josekit::jwk::Jwk::from_map(pubkey_jwk.as_object().unwrap().clone()).unwrap();

    let params = GenerateVCParams {
        issuer,
        vct,
        private_key: private_key.as_bytes().to_vec(),
        jwk,
        account_name,
        ip_address,
        route_networks: route_network_addresses,
        dns_addresses,
        group_name: group,
        vc_expires_in,
    };
    match generate_sd_jwt_vc(params) {
        Ok(vc) => {
            println!("VC={vc}");
            std::fs::write("vc.jwt", vc)?;
        }
        Err(e) => {
            eprintln!("{e:?}");
        }
    }

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

/// カンマ区切りの分割された文字列を取得
fn parse_split_string(s: &str) -> Vec<String> {
    let res: Vec<String> = s.split(',').map(String::from).collect();
    if res.len() == 1 && res[0] == *"" {
        vec![]
    } else {
        res
    }
}
