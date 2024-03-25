use josekit::{jwk, jwt};
use josekit::{jws::EdDSA, Value};
use sd_jwt_payload::{KeyBindingJwtClaims, SdJwt, SdObjectDecoder, Sha256Hasher};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Holderの公開鍵をファイルから読み込み
    const ISSUER_PUBLIC_KEY: &str = "../issuer/issuer_public_key_ed25519.pem";

    // Holderから提出されたVP（署名付きJWTとして）
    let sd_jwt = "eyJ0eXAiOiJlbW90aW9ubGluaytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsia3R5IjoiT0tQIiwidXNlIjoic2lnIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJ1cVlhOTVaN0tIVGRabWdIUTZDRFF3LTNndzBEbEZTTVVvaTNzX0FRaDBNIn0sIl9zZCI6WyJNbjYxcFlyNlk1RExSbm85NnpOMzdCUGM2UHRjYUpFMGdpWXUwRzFwYWZjIiwidGd5b1M2UFc1cGZBSm4xaG15WG9FSzg1U19meTVLc1BYbmxIa1NEWTlCUSIsIktON2JRdGpCamxEZndBVy1TTERPaTE3SW9fMUUtcjk0elk0eHp1T3BKVnciLCJlaFBvdl9nc1oxWXhTT1hGUXBaZGRjOEpKWDFuVXZHSDRlMzB2aFZKVTM0IiwidHBNaEtJZE5ieDRrOU1qanV4dERIdEdxblQzOE1TTjR1aWkzTU42eDJZcyIsIk5tUFZfaFVJOHVmWWFfMEwwZ0M2MFdKT3dJTWpmOXQ3QzRTaE9VdF95WE0iLCJzejBpZ3pjZmExSEVzUUE3ZEtVaWwySl95Qk5CWVBJNTl0SXNHWnl5WkwwIiwiMWVhNnczWFVjYmJPN2k3NjAzTjk3QW9vUlRueklJLXNVamFCZGlNRFYwbyIsIjhkWXpDenFzaWFQQkZ2TDhGc1JONVJtWlRWb0hFYnNtb2M5YW1hajlpc2MiXSwiaXNzIjoiZW1vdGlvbmxpbmstaXNzdWVyIiwidmN0IjoiZW1vdGlvbmxpbmsiLCJhdWQiOiJleGFtcGxlX2dyb3VwX2V4YW1wbGVfYWNjb3VudCIsImlhdCI6MTcxMTMzNzcwOSwiZXhwIjoxNzExOTQyNTA5fQ.5OEZoRUx_DXm9sB5k1hXC8F4ghp5spQBdYHq7HIPB9EdsH9gQM3_eTsllbA5c-Sqwp9rZK9T-keEreVtcfIpCg~WyJzSHdTenBobGRVSi1HZHU1NHZvRkNxeTd3N1UtdUpEd2dkRVRNNTJMIiwgImRuc19hZGRyZXNzZXMiLCBbIjEwLjI1NC4xMC4xIiwiZmMwMDpmZjAwOjA6YTo6MTA6MSJdXQ~WyJ4YXZkb3FhN3M5a1hxaGI1Z1pwQzJVb3VsaTR2a3ppZ1BJb0ttQVhzIiwgInJvdXRlX25ldHdvcmtzIiwgWyIxMC4yNTQuMC4wLzE2IiwiZmMwMDpmZjAwOjA6YTo6LzY0Il1d~WyJMaGk3cXlRRjNncnp3M3NvZjR6czZyN2otNmR6NFR1Y0t1RWc0U19BIiwgImFjY291bnRfbmFtZSIsICJleGFtcGxlX2FjY291bnQiXQ~WyJ0eWdEUFJPOTZaelNoXzF1Rjg3U2lwdFpoZXFTX3owZXc0Vk5LdGhxIiwgImdyb3VwX25hbWUiLCAiZXhhbXBsZV9ncm91cCJd~WyJPeFlSLWtLRG1aaVFBQmNueUtQUkwzUEU4bDFiUkNFQ2VkdUl0ZzF4IiwgImlwX2FkZHJlc3NlcyIsIFsiMTAuMjU0LjEwMC4yIiwiZmMwMDpmZjAwOjA6YTo6MTAwOjIiXV0~eyJhbGciOiJFZERTQSIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJlbC1zZXJ2ZXIiLCJpYXQiOjE3MTEzMzc3NDAsImV4cCI6MTcxMTM0MTM0MCwibm9uY2UiOiJub25jZSIsInNkX2hhc2giOiJzQ3hPZXBxcFlvXzlKS3hqcXVweVRDbHRsRWUxX3o2SnItV3V0YU5CVU1rIn0.d8Gzhnl5Y0RF7gIqU6cyWn70XQbhO4npFfgdpwUK1sJz2Du-inC2MaypVufzhL30j28D1L-1yLWRSpejrLXYCg";

    // Decoding the SD-JWT
    // Extract the payload from the JWT of the SD-JWT after verifying the signature.
    let public_key = std::fs::read(ISSUER_PUBLIC_KEY).unwrap();
    let issuer_verifier = EdDSA.verifier_from_pem(public_key)?;

    let now = std::time::SystemTime::now();

    let sd_jwt: SdJwt = SdJwt::parse(&sd_jwt)?;

    // Holder の公開鍵を SD-JWT の cnf から取り出す
    let (sd_jwt_payload, sd_jwt_header) = jwt::decode_with_verifier(&sd_jwt.jwt, &issuer_verifier)?;
    println!("sd-jwt's header={:?}", sd_jwt_header.to_string());
    println!("sd-jwt's payload={:?}", sd_jwt_payload.to_string());

    // sd-jwt の header の typ が emotionlink+sd-jwt であるかチェック
    match sd_jwt_header.token_type() {
        Some("emotionlink+sd-jwt") => (),
        Some(_) => panic!("token type is not emotionlink+sd-jwt!"),
        _ => panic!("token type is None!"),
    }

    // VP の exp が期限切れになっていないかチェック
    match sd_jwt_payload.expires_at() {
        Some(exp) => {
            if exp < now {
                panic!("kb-jwt's exp is expired!")
            }
        }
        _ => panic!("kb-jwt has no exp!"),
    }

    let holder_public_key_jwk = match sd_jwt_payload.claim("cnf") {
        Some(value) => {
            let key_materials = if let Some(data) = value.as_object() {
                data
            } else {
                panic!("failed to as_object!");
            };
            jwk::Jwk::from_map(key_materials.clone())?
        }
        _ => panic!("there is no holder's public key!"),
    };
    let holder_verifier = EdDSA.verifier_from_jwk(&holder_public_key_jwk)?;

    let (kb_jwt_payload, kb_jwt_header) = match sd_jwt.key_binding_jwt {
        Some(key_binding_jwt) => jwt::decode_with_verifier(&key_binding_jwt, &holder_verifier)?,
        _ => panic!("key_binding_jwt is None"),
    };
    println!("kb-jwt's header={:?}", kb_jwt_header.to_string());
    println!("kb-jwt's payload={:?}", kb_jwt_payload.to_string());
    println!("");

    // kb-jwt の header の typ が kb+jwt であるかチェック
    match kb_jwt_header.token_type() {
        Some("kb+jwt") => (),
        Some(_) => panic!("token type is not kb+jwt!"),
        _ => panic!("token type is None!"),
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
    if let Some(Value::String(sd_hash)) = kb_jwt_payload.claim("sd_hash") {
        if &key_binding_jwt.sd_hash != sd_hash {
            panic!("sd_hash is not correct!");
        }
    } else {
        panic!("sd_hash is not correct!");
    }

    // kb-jwt の aud に el-server が含まれているかチェック
    match kb_jwt_payload.audience() {
        Some(aud) if aud.contains(&"el-server") => (),
        _ => panic!("audience is not contains el-server!"),
    }

    // VC の exp が期限切れになっていないかチェック
    match kb_jwt_payload.expires_at() {
        Some(exp) => {
            if exp < now {
                panic!("kb-jwt's exp is expired!")
            }
        }
        _ => panic!("kb-jwt has no exp!"),
    }

    // Decode the payload by providing the disclosures that were parsed from the SD-JWT.
    let decoder = SdObjectDecoder::new_with_sha256();
    let decoded = decoder.decode(sd_jwt_payload.claims_set(), &sd_jwt.disclosures)?;
    println!(
        "decoded object: {}",
        serde_json::to_string_pretty(&decoded)?
    );

    Ok(())
}
