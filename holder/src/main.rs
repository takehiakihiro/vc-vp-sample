use anyhow::{anyhow, Result};
use chrono::{TimeDelta, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json;
use std::fs;

fn main() -> Result<()> {
    // 秘密鍵をファイルから読み込み
    let private_key_pem = fs::read("holder_private_key.pem")?;

    println!("loaded private key");

    // 現在時刻
    let now = Utc::now();
    let exp = match TimeDelta::try_days(1) {
        Some(one_day) => (now + one_day).timestamp(),
        None => {
            println!("Error occurred");
            now.timestamp() + 10
        }
    };
    let now = now.timestamp();

    // VPのペイロード（患者IDのみを含む）
    let claims = serde_json::json!({
        "sub": "1234567890",  // 患者ID
        "iss": "VCVPSampleHolder",  // Holderを識別するための情報
        "iat": now,  // 発行時刻
        "exp": exp,  // 有効期限を1週間後に設定
    });

    println!("claims: {:?}", claims);

    let key = EncodingKey::from_rsa_pem(&private_key_pem)?;

    // VPに署名
    let token = encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| anyhow!("JWT encoding error: {}", e))?;

    println!("Signed VP: {}", token);

    Ok(())
}
