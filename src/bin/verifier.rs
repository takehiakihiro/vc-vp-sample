use anyhow::{anyhow, Result};
use jsonwebtoken::{jwk::Jwk, Algorithm, DecodingKey, Validation};
use sd_jwt_payload::{KeyBindingJwtClaims, SdJwt, SdObjectDecoder, Sha256Hasher};
use serde_json::Value;
use std::{fs::File, io::Read};

fn main() -> Result<()> {
    // Holderの公開鍵をファイルから読み込み
    #[cfg(feature = "EdDSA")]
    const ISSUER_PUBLIC_KEY: &str = "issuer_public_key_ed25519.pem";
    #[cfg(feature = "ES256")]
    const ISSUER_PUBLIC_KEY: &str = "issuer_public_key_ES256.pem";

    // Holderから提出されたVP（署名付きJWTとして）
    let vp = std::fs::read_to_string("vp.jwt").unwrap();

    // Decoding the SD-JWT
    // Extract the payload from the JWT of the SD-JWT after verifying the signature.
    let public_key = read_pem_file(ISSUER_PUBLIC_KEY)
        .map_err(|e| anyhow!("failed to read pem e={}", e.to_string()))?;
    println!("public_key: {public_key:?}");
    #[cfg(feature = "EdDSA")]
    let issuer_decoding_key = DecodingKey::from_ed_pem(&public_key)?;
    #[cfg(feature = "ES256")]
    let issuer_decoding_key = DecodingKey::from_ec_pem(&public_key)?;
    println!("issuer_decoding_key");

    let sd_jwt: SdJwt = SdJwt::parse(&vp)?;

    // Holder の公開鍵を SD-JWT の cnf から取り出す
    #[cfg(feature = "EdDSA")]
    let mut validation = Validation::new(Algorithm::EdDSA);
    #[cfg(feature = "ES256")]
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["fujita-app"]);
    let vc_token = jsonwebtoken::decode::<Value>(&sd_jwt.jwt, &issuer_decoding_key, &validation)?;
    println!("VC header={:?}", vc_token.header);
    println!("VC payload={:?}", vc_token.claims);

    // VC の header の typ が vc+sd-jwt であるかチェック
    match vc_token.header.typ {
        Some(v) => match v.as_str() {
            "vc+sd-jwt" => {}
            _ => panic!("vc header typ is not vc+sd-jwt!"),
        },
        _ => panic!("vc header typ is None!"),
    }

    // VC の exp が期限切れになっていないかチェック
    // decodeで期限切れチェックはすでに行っている

    let holder_public_key_jwk = match vc_token.claims.get("cnf") {
        Some(value) => {
            let jwk = match value.get("jwk") {
                Some(v) => v,
                _ => panic!("there is no jwk"),
            };
            json_to_jwk(jwk)?
        }
        _ => panic!("there is no holder's public key!"),
    };
    let holder_decoding_key = DecodingKey::from_jwk(&holder_public_key_jwk)?;

    let vp_token = match sd_jwt.key_binding_jwt {
        Some(vp_jwt) => {
            #[cfg(feature = "EdDSA")]
            let mut validation = Validation::new(Algorithm::EdDSA);
            #[cfg(feature = "ES256")]
            let mut validation = Validation::new(Algorithm::ES256);
            validation.set_audience(&["el-server"]);
            jsonwebtoken::decode::<Value>(&vp_jwt, &holder_decoding_key, &validation)?
        }
        _ => panic!("key_binding_jwt is None"),
    };
    println!("kb-jwt's header={:?}", vp_token.header);
    println!("kb-jwt's payload={:?}", vp_token.claims);
    println!();

    // VP の header の typ が kb+jwt であるかチェック
    match vp_token.header.typ {
        Some(v) => match v.as_str() {
            "kb+jwt" => {}
            _ => panic!("vc header typ is not vc+sd-jwt!"),
        },
        _ => panic!("vc header typ is None!"),
    }

    // kb-jwt の sd_hash の値が一致するかチェック
    let hasher = Sha256Hasher::new();
    let key_binding_jwt = KeyBindingJwtClaims::new(
        &hasher,
        sd_jwt.jwt.clone(),
        sd_jwt.disclosures.clone(),
        "dummy".to_string(),
        "dummy".to_string(),
        0,
    );
    println!("sd_hash={}", key_binding_jwt.sd_hash);
    if let Some(Value::String(sd_hash)) = vp_token.claims.get("sd_hash") {
        if &key_binding_jwt.sd_hash != sd_hash {
            panic!("sd_hash is not correct!");
        }
    } else {
        panic!("sd_hash is not correct!");
    }

    println!("vp_token payload={:?}", vp_token.claims);
    // Decode the payload by providing the disclosures that were parsed from the SD-JWT.
    let decoder = SdObjectDecoder::new_with_sha256();
    let obj = vc_token.claims.as_object().unwrap();
    println!("obj={obj:?}");
    println!("disclosures len={}", sd_jwt.disclosures.len());
    let decoded = decoder.decode(obj, &sd_jwt.disclosures)?;
    println!(
        "decoded object: {}",
        serde_json::to_string_pretty(&decoded)?
    );

    Ok(())
}

/// PEMファイルの読み込み
fn read_pem_file(file_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = vec![];
    file.read_to_end(&mut contents)?;
    // let pem = parse(contents)?;
    // Ok(pem.contents().to_vec())
    Ok(contents)
}

/// JSONからJWK
fn json_to_jwk(jwk: &Value) -> Result<Jwk> {
    serde_json::from_value(jwk.clone()).map_err(|e| anyhow!("failed to convert jwk e={}.", e))
}
