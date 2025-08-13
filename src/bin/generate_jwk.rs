use anyhow::Result;
use base64::Engine;
#[cfg(feature = "EdDSA")]
use ring::signature::Ed25519KeyPair;
use serde_json::Value;

fn main() -> Result<()> {
    #[cfg(feature = "EdDSA")]
    const KEY: &str = "issuer_private_key_ed25519.pem";
    #[cfg(feature = "ES256")]
    const KEY: &str = "issuer_public_key_ES256.pem";

    // ======================= Holder part =======================
    // PEMファイルから秘密鍵を読み込み、公開鍵を取り出す
    #[cfg(feature = "EdDSA")]
    {
        let priv_key = read_pem_file(KEY)?;
        println!("priv_key={:?}", priv_key);
        let key_pair = generate_key_pair(&priv_key)?;
        // 公開鍵をJWK形式に変換
        let pubkey_jwk = public_key_to_jwk(&key_pair)?;
        println!("pubkey_jwk={}", pubkey_jwk);
    }
    #[cfg(feature = "ES256")]
    {
        use anyhow::anyhow;
        let pubkey_jwk = public_key_to_jwk(KEY)
            .map_err(|e| anyhow!("failed to convert to jwk e={}", e.to_string()))?;
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

    let secret_key = std::fs::read_to_string(file_path)?;
    let public_key = p256::PublicKey::from_public_key_pem(&secret_key)?;
    // 座標を取り出す (圧縮なしのポイントにする: to_encoded_point(false))
    let encoded_point = public_key.to_encoded_point(false);
    let x_bytes = encoded_point.x().ok_or("Failed to get X coordinate")?;
    let y_bytes = encoded_point.y().ok_or("Failed to get Y coordinate")?;

    // ---- (3) x, y を Base64URL (padding なし) でエンコード
    let x = URL_SAFE_NO_PAD.encode(x_bytes);
    let y = URL_SAFE_NO_PAD.encode(y_bytes);

    // ---- (4) 必要なフィールドを揃えて JWK (公開鍵) を生成
    // ES256(P-256) の JWK には "kty", "crv", "x", "y" が必須となります
    // "alg" や "kid", "use", "key_ops" 等は必要に応じて追加してください
    let jwk = serde_json::json!({
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
