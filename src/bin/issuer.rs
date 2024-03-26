use josekit::jwk::alg::ed::EdKeyPair;
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use rand::seq::SliceRandom; // SliceRandomトレイトをインポート
use rand::thread_rng; // 乱数生成器をインポート
use sd_jwt_payload::{Disclosure, SdJwt, SdObjectEncoder, HEADER_TYP};
use serde_json::{json, Value};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    const ISSUER_PRIVATE_KEY: &str = "issuer_private_key_ed25519.pem";
    const HOLDER_PRIVATE_KEY: &str = "holder_private_key_ed25519.pem";

    // ======================= Holder part =======================
    let private_pem_file_content = std::fs::read(HOLDER_PRIVATE_KEY)?;
    let key_pair = EdKeyPair::from_pem(private_pem_file_content)?;
    let jwk = key_pair.to_jwk_public_key();
    let pubkey_jwk = serde_json::from_str(&jwk.to_string())?;

    // ======================= Issuer part =======================
    let account_name = "example_account";
    let ip_addresses = ["10.254.100.2", "fc00:ff00:0:a::100:2"];
    let dns_addresses = ["10.254.10.1", "fc00:ff00:0:a::10:1"];
    let route_networks = ["10.254.0.0/16", "fc00:ff00:0:a::/64"];
    let group_name = "example_group";
    let real_name = "takehiakihiro";
    let company = "freebit";

    let mut object = json!({
      "account_name": account_name,
      "ip_addresses": ip_addresses,
      "dns_addresses": dns_addresses,
      "route_networks": route_networks,
      "group_name": group_name,
      "real_name": real_name,
      "company": company,
    });

    let mut inner_jwk = serde_json::Map::new();
    inner_jwk.insert("jwk".to_string(), pubkey_jwk);
    let cnf = match serde_json::to_value(inner_jwk) {
        Ok(v) => v,
        _ => panic!("failed to add"),
    };
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
        encoder.conceal("/real_name", None)?,
        encoder.conceal("/company", None)?,
    ];

    encoder.add_decoys("", 2)?; // Add decoys to the top level.

    // encoder.add_sd_alg_property();

    println!(
        "encoded object: {}",
        serde_json::to_string_pretty(encoder.object()?)?
    );

    // Create the JWT.
    // Creating JWTs is outside the scope of this library, josekit is used here as an example.
    let mut header = JwsHeader::new();
    let token_type = format!("vc+{}", HEADER_TYP);
    header.set_token_type(token_type);
    header.set_algorithm("EdDSA"); // EdDSA署名アルゴリズムの指定

    // Use the encoded object as a payload for the JWT.
    let mut payload = JwtPayload::from_map(encoder.object()?.clone())?;
    payload.set_issuer("emotionlink-issuer");
    let _ = payload.set_claim("vct", Some(Value::from("emotionlink")));
    let audience: String = format!("{}_{}", group_name, account_name);
    let audiences = vec![audience];
    payload.set_audience(audiences);
    let now = std::time::SystemTime::now();
    let expires_at = now + std::time::Duration::from_secs(7 * 24 * 60 * 60);
    payload.set_issued_at(&now);
    payload.set_expires_at(&expires_at);

    let private_key = std::fs::read(ISSUER_PRIVATE_KEY).unwrap();
    let signer = EdDSA.signer_from_pem(private_key)?;
    println!("loaded signer's private key");
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

    // Create an SD_JWT by collecting the disclosures and creating an `SdJwt` instance.
    let mut disclosures: Vec<String> = disclosures
        .into_iter()
        .map(|disclosure| disclosure.to_string())
        .collect();

    // 乱数生成器を取得
    let mut rng = thread_rng();
    // ベクタの中身をランダムに入れ替える
    disclosures.shuffle(&mut rng);

    // disclosures の配列の中身をランダムに並べ替える
    let sd_jwt: SdJwt = SdJwt::new(jwt, disclosures, None);
    let sd_jwt: String = sd_jwt.presentation();
    println!("VC={}", sd_jwt);
    std::fs::write("vc.jwt".to_string(), sd_jwt)?;

    Ok(())
}
