use chrono::Utc;
use ed25519_dalek::{Keypair, Signer};
use rand::rngs::OsRng;
use sd_jwt_payload::{Payload, Scope, SDJWTCreator};
use serde_json::json;
use std::fs::File;
use std::io::Write;

fn main() {
    // 秘密鍵と公開鍵のペアを生成
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    // 秘密鍵をファイルに保存
    let mut file = File::create("issuer_private_key_ed25519.pem").unwrap();
    file.write_all(&keypair.secret.to_bytes()).unwrap();

    // 公開鍵をファイルに保存
    let mut file = File::create("issuer_public_key_ed25519.pem").unwrap();
    file.write_all(&keypair.public.to_bytes()).unwrap();

    // VCのペイロードを作成
    let payload = json!({
        "iss": "did:example:issuer",
        "sub": "did:example:subject",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://example.com/credentials/v1"
            ],
            "type": ["VerifiableCredential", "AccountCredential"],
            "credentialSubject": {
                "account_name": "example_account",
                "ip_addresses": ["192.168.0.1", "192.168.0.2"],
                "dns_addresses": ["example.com", "example.org"],
                "route_networks": ["10.0.0.0/8", "172.16.0.0/12"],
                "group_name": "example_group"
            }
        }
    });

    // SDスコープを設定
    let sd_scope = Scope::new()
        .add_hide("account_name")
        .add_hide("ip_addresses")
        .add_hide("dns_addresses")
        .add_hide("route_networks")
        .add_hide("group_name");

    // SD-JWTを生成
    let sd_jwt_creator = SDJWTCreator::new()
        .algorithm("EdDSA")
        .hash_algorithm("sha-256")
        .key(keypair.secret.as_bytes())
        .kid("did:example:issuer#key-1");

    let sd_jwt = sd_jwt_creator.encode(&Payload::from_json(&payload), &sd_scope).unwrap();

    println!("SD-JWT: {}", sd_jwt);
}
