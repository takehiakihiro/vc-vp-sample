use josekit::jwk::alg::ed::EdKeyPair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

fn main() {
    let private_pem_file_content = std::fs::read("issuer_private_key_ed25519.pem").unwrap();
    let key_pair = EdKeyPair::from_pem(private_pem_file_content).unwrap();
    let jwk = key_pair.to_jwk_public_key();
    println!("jwk={:?}", jwk.to_string());
    let der = key_pair.to_der_public_key();
    let hex_strings: Vec<String> = der.iter().map(|byte| format!("{:02x}", byte)).collect();
    println!("der={:?}", hex_strings.join(""));


    // Base64urlエンコードされた文字列
    let encoded_str = b"yTIURJAM9zQNEVZ0EamLf0up2fkFIGOkRIXzrR-PRNo";
    let mut buffer = Vec::<u8>::new();

    // Base64urlデコードを試みる
    URL_SAFE_NO_PAD.decode_vec(encoded_str, &mut buffer).unwrap();
    let hex_strings: Vec<String> = buffer.iter().map(|byte| format!("{:02x}", byte)).collect();
    println!("decoded_bytes={:?}", hex_strings.join(""));
}
