use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use sd_jwt_payload::{KeyBindingJwtClaims, SdJwt, Sha256Hasher};
use serde_json::Value;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 秘密鍵をファイルから読み込み
    const ISSUER_PUBLIC_KEY: &str = "../issuer/issuer_public_key_ed25519.pem";
    const HOLDER_PRIVATE_KEY: &str = "../issuer/holder_private_key_ed25519.pem";

    const VC: &str = "eyJ0eXAiOiJlbW90aW9ubGluaytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsia3R5IjoiT0tQIiwidXNlIjoic2lnIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJ1cVlhOTVaN0tIVGRabWdIUTZDRFF3LTNndzBEbEZTTVVvaTNzX0FRaDBNIn0sIl9zZCI6WyJNbjYxcFlyNlk1RExSbm85NnpOMzdCUGM2UHRjYUpFMGdpWXUwRzFwYWZjIiwidGd5b1M2UFc1cGZBSm4xaG15WG9FSzg1U19meTVLc1BYbmxIa1NEWTlCUSIsIktON2JRdGpCamxEZndBVy1TTERPaTE3SW9fMUUtcjk0elk0eHp1T3BKVnciLCJlaFBvdl9nc1oxWXhTT1hGUXBaZGRjOEpKWDFuVXZHSDRlMzB2aFZKVTM0IiwidHBNaEtJZE5ieDRrOU1qanV4dERIdEdxblQzOE1TTjR1aWkzTU42eDJZcyIsIk5tUFZfaFVJOHVmWWFfMEwwZ0M2MFdKT3dJTWpmOXQ3QzRTaE9VdF95WE0iLCJzejBpZ3pjZmExSEVzUUE3ZEtVaWwySl95Qk5CWVBJNTl0SXNHWnl5WkwwIiwiMWVhNnczWFVjYmJPN2k3NjAzTjk3QW9vUlRueklJLXNVamFCZGlNRFYwbyIsIjhkWXpDenFzaWFQQkZ2TDhGc1JONVJtWlRWb0hFYnNtb2M5YW1hajlpc2MiXSwiaXNzIjoiZW1vdGlvbmxpbmstaXNzdWVyIiwidmN0IjoiZW1vdGlvbmxpbmsiLCJhdWQiOiJleGFtcGxlX2dyb3VwX2V4YW1wbGVfYWNjb3VudCIsImlhdCI6MTcxMTMzNzcwOSwiZXhwIjoxNzExOTQyNTA5fQ.5OEZoRUx_DXm9sB5k1hXC8F4ghp5spQBdYHq7HIPB9EdsH9gQM3_eTsllbA5c-Sqwp9rZK9T-keEreVtcfIpCg~WyJzSHdTenBobGRVSi1HZHU1NHZvRkNxeTd3N1UtdUpEd2dkRVRNNTJMIiwgImRuc19hZGRyZXNzZXMiLCBbIjEwLjI1NC4xMC4xIiwiZmMwMDpmZjAwOjA6YTo6MTA6MSJdXQ~WyJ4YXZkb3FhN3M5a1hxaGI1Z1pwQzJVb3VsaTR2a3ppZ1BJb0ttQVhzIiwgInJvdXRlX25ldHdvcmtzIiwgWyIxMC4yNTQuMC4wLzE2IiwiZmMwMDpmZjAwOjA6YTo6LzY0Il1d~WyJMaGk3cXlRRjNncnp3M3NvZjR6czZyN2otNmR6NFR1Y0t1RWc0U19BIiwgImFjY291bnRfbmFtZSIsICJleGFtcGxlX2FjY291bnQiXQ~WyJ0eWdEUFJPOTZaelNoXzF1Rjg3U2lwdFpoZXFTX3owZXc0Vk5LdGhxIiwgImdyb3VwX25hbWUiLCAiZXhhbXBsZV9ncm91cCJd~WyJPRXJKQXZvOXg1NTJCRVZKQTk4bVk2Wmk2LW5QQklXRnlDemo0c3pTIiwgInJlYWxfbmFtZSIsICJ0YWtlaGlha2loaXJvIl0~WyJPeFlSLWtLRG1aaVFBQmNueUtQUkwzUEU4bDFiUkNFQ2VkdUl0ZzF4IiwgImlwX2FkZHJlc3NlcyIsIFsiMTAuMjU0LjEwMC4yIiwiZmMwMDpmZjAwOjA6YTo6MTAwOjIiXV0~WyJUTUp1NzR5UzRINWFsUEk0Y0R5T192ZE9WYTM3c0R6NEFNdld0eWRMIiwgImNvbXBhbnkiLCAiZnJlZWJpdCJd~";

    let sd_jwt: SdJwt = SdJwt::parse(&VC)?;

    let public_key = std::fs::read(ISSUER_PUBLIC_KEY).unwrap();
    let issuer_verifier = EdDSA.verifier_from_pem(public_key)?;
    let (payload, header) = jwt::decode_with_verifier(&sd_jwt.jwt, &issuer_verifier)?;
    println!("sd-jwt's header={:?}", header.to_string());
    println!("sd-jwt's payload={:?}", payload.to_string());
    println!("");

    // disclosures の中から、公開したいものを Base64url decode して中身を見て選別する
    let mut disclosures = Vec::new();

    for encoded_str in sd_jwt.disclosures {
        let mut buffer = Vec::<u8>::new();
        let check_strings = [
            "ip_addresses",
            "dns_addresses",
            "route_networks",
            "account_name",
            "group_name",
        ];

        // Base64urlデコードを試みる
        if URL_SAFE_NO_PAD
            .decode_vec(encoded_str.as_bytes(), &mut buffer)
            .is_ok()
        {
            // デコードされた文字列を取得
            if let Ok(decoded_str) = String::from_utf8(buffer) {
                // JSONとしてパース
                if let Ok(json) = serde_json::from_str::<Value>(&decoded_str) {
                    println!("checking decoded={:?}, encoded={}", json, encoded_str);
                    // JSONが配列形式であり、2番目の要素が指定した文字列のいずれかに一致するかチェック
                    if json.as_array().map_or(false, |arr| {
                        arr.get(1).map_or(false, |second_element| {
                            check_strings.contains(&second_element.as_str().unwrap_or(""))
                        })
                    }) {
                        // 条件を満たす場合、元のBase64urlエンコードされた文字列を保存
                        println!("MATCH! decoded={:?}, encoded={}", json, encoded_str);
                        disclosures.push(encoded_str.to_string());
                    }
                }
            }
        }
    }
    let nonce = "nonce".to_string();
    let audience = "el-server".to_string();
    let hasher = Sha256Hasher::new();
    let key_binding_jwt = KeyBindingJwtClaims::new(
        &hasher,
        sd_jwt.jwt.clone(),
        disclosures.clone(),
        nonce,
        audience,
        0,
    );

    let holder_private_key = std::fs::read(HOLDER_PRIVATE_KEY).unwrap();
    let signer = EdDSA.signer_from_pem(holder_private_key)?;
    let mut header = JwsHeader::new();
    header.set_algorithm("EdDSA"); // EdDSA署名アルゴリズムの指定
    header.set_token_type("kb+jwt");
    let mut payload = JwtPayload::new();
    payload.set_audience([key_binding_jwt.aud.clone()].to_vec());
    let now = std::time::SystemTime::now();
    payload.set_issued_at(&now);
    let expires_at = now + std::time::Duration::from_secs(60 * 60);
    payload.set_expires_at(&expires_at);
    payload.set_claim("nonce", Some(Value::String(key_binding_jwt.nonce)))?;
    payload.set_claim("sd_hash", Some(Value::String(key_binding_jwt.sd_hash)))?;
    let key_binding_jwt = jwt::encode_with_signer(&payload, &header, &signer)?;
    println!("kb-jwt: {:?}", key_binding_jwt);
    println!("");

    let sd_jwt: SdJwt = SdJwt::new(sd_jwt.jwt, disclosures.clone(), Some(key_binding_jwt));
    let sd_jwt: String = sd_jwt.presentation();

    println!("VP={:?}", sd_jwt);

    Ok(())
}
