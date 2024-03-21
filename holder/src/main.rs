use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use sd_jwt_payload::{KeyBindingJwtClaims, SdJwt, Sha256Hasher};
use serde_json::Value;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 秘密鍵をファイルから読み込み
    const ISSUER_PUBLIC_KEY: &str = "../issuer/issuer_public_key_ed25519.pem";
    const HOLDER_PRIVATE_KEY: &str = "../issuer/holder_private_key_ed25519.pem";

    const VC: &str = "eyJ0eXAiOiJlbW90aW9ubGluaytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJjbmYiOnsia3R5IjoiT0tQIiwidXNlIjoic2lnIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJ1cVlhOTVaN0tIVGRabWdIUTZDRFF3LTNndzBEbEZTTVVvaTNzX0FRaDBNIn0sIl9zZCI6WyJMZmYzdU82QXhfZW9nYzlYWTNpVnRSeTEwT1h5RS1nQjdQc3BzNUlEVFJRIiwiRG8zOHlxQ3A1UUIyODFtdEQxdkpxanYyNmhTZThXSzFSTkFwc2k5TVFVcyIsIjgtREhnZ082VV9aOUR5NmtlVHNfM19fZU52T0RZdWphVHkyVTNNUUFNOTQiLCJfXzdqWHhzVWduY0JGNGk0Y2Q0UTlVMks5b3dVaE5vYlpfYk1FRzYtRUxJIiwiRjJQWWk2WFpVeW9WczN5QWNWaFJkZHZwaDBNSGt1dGlLWkZ1MVhXaHRHNCIsIlhQVHNMX2lzbmZ0R0dNZGc1WFZUbGozX0sxVm5GZS0ycXZXMmdhRTlzSFUiLCJWblg5SjUzUzlTWFlyTWF4ZzZqd2YzUlU0OFNBQ01VckRDanA5b1VnTXlRIiwiS2VlMDlsVzZJem4xYWsyRW5UdGFmeG44RV9wNHN4LU5STmtKQlRhTG1IbyIsIkx5MVRpd3FLazR3SURuNmczQlJsUHdZMjE0SkctX0JHdE1DNTJTRUtoaWsiXSwiYXVkIjoiZXhhbXBsZV9ncm91cF9leGFtcGxlX2FjY291bnQiLCJpYXQiOjE3MTA5OTM3NzgsImV4cCI6MTcxMTU5ODU3OH0.1UXlr9Dh8romq1phReUMkQBw0z5Jb2OJKhiqh6CjulwkDeH5o4YBFYP1Ya5SN6r4G48b9DXcs-cYDzWa9ef0Dg~WyJMZnp0VkJJNjdzMzQxdHN3V0NzcmE1c0NsRkNWM2hneHBsdDZfX0VXIiwgImFjY291bnRfbmFtZSIsICJleGFtcGxlX2FjY291bnQiXQ~WyJKdjNOQXpkaWdEeHJacXNCTUtzbUwxV0VtWXE4NkVMS21jWkpOMEFDIiwgImlwX2FkZHJlc3NlcyIsIFsiMTAuMjU0LjEwMC4yIiwiZmMwMDpmZjAwOjA6YTo6MTAwOjIiXV0~WyIzdXl0Y19CeW5qYVpVbHVqVHlXRU8tX2MyeGlQX0RnWnlXYmpQVEhKIiwgImRuc19hZGRyZXNzZXMiLCBbIjEwLjI1NC4xMC4xIiwiZmMwMDpmZjAwOjA6YTo6MTA6MSJdXQ~WyIyWEs0Mk9NUjRoS2hMRlZJQVRVSnJ0NjdIQVg4TUJhaUY2REFpNmg2IiwgInJvdXRlX25ldHdvcmtzIiwgWyIxMC4yNTQuMC4wLzE2IiwiZmMwMDpmZjAwOjA6YTo6LzY0Il1d~WyJMTWN0YUtZdmN0VlRIaG9ZSklSZ0U1bTQzZHhmMTRKcDNkMl9pcVltIiwgImdyb3VwX25hbWUiLCAiZXhhbXBsZV9ncm91cCJd~WyJoOFI3QmdTNlk3Tk50VURPaFBIZmVtenBOLXpOYjVRTDJ0RlBGTmJFIiwgInJlYWxfbmFtZSIsICJ0YWtlaGlha2loaXJvIl0~WyJ0ZndMSG5UZXFMelp4aVRrM1hLQkoxZnpMdzhxR0d3Q0JyQzFtRkJmIiwgImNvbXBhbnkiLCAiZnJlZWJpdCJd~";

    let sd_jwt: SdJwt = SdJwt::parse(&VC)?;

    let public_key = std::fs::read(ISSUER_PUBLIC_KEY).unwrap();
    let issuer_verifier = EdDSA.verifier_from_pem(public_key)?;
    let (payload, header) = jwt::decode_with_verifier(&sd_jwt.jwt, &issuer_verifier)?;
    println!("sd-jwt's header={:?}", header.to_string());
    println!("sd-jwt's payload={:?}", payload.to_string());
    println!("");

    // TODO: disclosures の中から、公開したいものを Base64url decode して中身を見て選別する
    let disclosures: Vec<String> = sd_jwt.disclosures.iter().take(5).cloned().collect();
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
