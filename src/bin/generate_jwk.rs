use anyhow::{anyhow, Result};
use base64::Engine;
#[cfg(feature = "EdDSA")]
use ring::signature::Ed25519KeyPair;
use serde_json::Value;
use std::{collections::BTreeMap, env};

fn main() -> Result<()> {
    // #[cfg(feature = "EdDSA")]
    // const KEY: &str = "issuer_private_key_ed25519.pem";
    // #[cfg(feature = "ES256")]
    // const KEY: &str = "issuer_public_key_ES256.pem";
    // ==== 1) 引数から鍵ファイルパスを取得 ====
    let key_path = env::args().nth(1).ok_or_else(|| {
        anyhow!("鍵ファイル（公開鍵PEM）のパスを起動引数の1番目に指定してください。例: cargo run --bin generate_jwk -- issuer_public_key_ES256.pem")
    })?;

    // ======================= Holder part =======================
    // PEMファイルから秘密鍵を読み込み、公開鍵を取り出す
    #[cfg(feature = "EdDSA")]
    {
        let priv_key = read_pem_file(&key_path)?;
        println!("priv_key={:?}", priv_key);
        let key_pair = generate_key_pair(&priv_key)?;
        // 公開鍵をJWK形式に変換
        let pubkey_jwk = public_key_to_jwk(&key_pair)?;
        println!("pubkey_jwk={}", pubkey_jwk);
    }
    #[cfg(feature = "ES256")]
    {
        use anyhow::anyhow;
        let pubkey_jwk = public_key_to_jwk(&key_path)
            .map_err(|e| anyhow!("failed to convert to jwk e={e:?}"))?;
        println!("pubkey_jwk={pubkey_jwk}");
    }

    Ok(())
}

/// PEMファイルから読み込み
#[cfg(feature = "EdDSA")]
fn read_pem_file(file_path: &str) -> Result<Vec<u8>> {
    use pem::parse;
    use std::io::Read as _;

    let mut file = std::fs::File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let pem = parse(contents)?;
    Ok(pem.contents().to_vec())
}

/// キーペア生成
#[cfg(feature = "EdDSA")]
fn generate_key_pair(secret_key_bytes: &[u8]) -> Result<Ed25519KeyPair> {
    let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(secret_key_bytes)?;
    Ok(key_pair)
}

/// 公開鍵からJWK形式
#[cfg(feature = "EdDSA")]
fn public_key_to_jwk(key_pair: &Ed25519KeyPair) -> Result<Value> {
    use base64::engine::general_purpose;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, OctetKeyPairParameters,
        OctetKeyPairType, PublicKeyUse,
    };
    use ring::signature::KeyPair as _;

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

/// 公開鍵からJWK形式
#[cfg(feature = "ES256")]
fn public_key_to_jwk(file_path: &str) -> Result<Value, Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::{elliptic_curve::sec1::ToEncodedPoint as _, pkcs8::DecodePublicKey};
    use serde_json::json;

    // PEM読み込み -> PublicKey化
    let pem = std::fs::read_to_string(file_path)?;
    let public_key = p256::PublicKey::from_public_key_pem(&pem)?;

    // 非圧縮ポイントから x,y を取得
    let encoded_point = public_key.to_encoded_point(false);
    let x_bytes = encoded_point.x().ok_or("Failed to get X coordinate")?;
    let y_bytes = encoded_point.y().ok_or("Failed to get Y coordinate")?;

    // Base64URL(=paddingなし)でエンコード
    let x = URL_SAFE_NO_PAD.encode(x_bytes);
    let y = URL_SAFE_NO_PAD.encode(y_bytes);

    // 必須フィールドでJWK作成
    let mut jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "alg": "ES256",
        "use": "sig",
    });

    // ==== 2) 一般的な kid（JWK Thumbprint RFC7638のSHA-256, Base64URL）を付与 ====
    let kid = jwk_thumbprint_sha256(&jwk)?;
    if let Some(obj) = jwk.as_object_mut() {
        obj.insert("kid".to_string(), Value::String(kid));
    }

    Ok(jwk)
}

/// RFC 7638 JWK Thumbprint (SHA-256, Base64URL, no padding) を算出
/// EC鍵では "crv","kty","x","y" を辞書順で並べた JSON をハッシュ対象にする
fn jwk_thumbprint_sha256(jwk: &Value) -> Result<String, Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    // 必要フィールドを取り出し、辞書順(BTreeMap)で整形
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or("missing kty")?;
    let crv = jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or("missing crv")?;
    let x = jwk.get("x").and_then(|v| v.as_str()).ok_or("missing x")?;
    let y = jwk.get("y").and_then(|v| v.as_str()).ok_or("missing y")?;

    let mut bmap = BTreeMap::new();
    bmap.insert("crv", crv);
    bmap.insert("kty", kty);
    bmap.insert("x", x);
    bmap.insert("y", y);

    // 余計な空白なしのJSONにシリアライズ（serde_json::to_string はデフォルトで緊縮表現）
    let canon = serde_json::to_string(&bmap)?;

    // SHA-256 -> Base64URL(no padding)
    let digest = Sha256::digest(canon.as_bytes());
    let kid = URL_SAFE_NO_PAD.encode(digest);

    Ok(kid)
}
