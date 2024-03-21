use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::fs;

fn main() -> Result<()> {
    // Holderの公開鍵をファイルから読み込み
    let public_key_pem = fs::read("../holder/holder_public_key.pem")?;

    // Holderから提出されたVP（署名付きJWTとして）
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3MDk4NzIwNDcsImlhdCI6MTcwOTc4NTY0NywiaXNzIjoiVkNWUFNhbXBsZUhvbGRlciIsInN1YiI6IjEyMzQ1Njc4OTAifQ.3Hp78rcrXcFaAZBW2E3f1S3tamabBXH9Wtp__PaMrjFWKruuKWN17zI4B8KY4vAEwmFaWWV1lNFtHPyUn9_JD_zTvMzXylbT6l-z6MPGYbU6fZkMuREieT1nDJEyfYd1dE9g-clhXo9OclVq04fQlz_1GRUTTuF1EyfOX9raxx0c3mDS0tzV6hSevcssYPiB-BoqlM47KHqmY4vJ4fqHw06jF35tULATjPp1JVQB8XJpl3EsNfNn17NEZT92-qGwluyEupJVhWONtnkzA4dRUYKklDV7HsZp-8oClWynkLC74WR2j1VPgoWqiJZO4xgSB7EhT34ZoqjZS68u-anjMw";

    let key = DecodingKey::from_rsa_pem(&public_key_pem)?;

    // VPの署名を検証
    let token_data = decode::<serde_json::Value>(&token, &key, &Validation::new(Algorithm::RS256))
        .map_err(|e| anyhow!("Failed to decode JWT: {}", e))?;

    println!("VP Claims: {:?}", token_data.claims);

    Ok(())
}
