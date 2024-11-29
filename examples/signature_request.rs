use cerberus_api::{
    client::SignerClient,
    SignGenericRequest,
    SignGenericResponse,
};
use ark_bn254::{Fq,g1::G1Affine};
use eigen_crypto_bls::BlsKeyPair;
use ark_ff::PrimeField;
use eigen_crypto_bls::BlsG1Point;
#[tokio::main]
async fn main() -> Result<(),Box<dyn std::error::Error>> {

    // In order to reproduce you must have cerberus running locally and then run 
    // grpcurl -plaintext -d '{"privateKey": "11507468573326802429316131015508122374943382748905752594830347872745975341448", "password": "Testacc1Testacc1"}' localhost:50051  keymanager.v1.KeyManager/ImportKey
    let mut client: SignerClient<tonic::transport::Channel> = SignerClient::connect("http://[::1]:50051").await?;
    let message = "Hello, world!";
    let message_bytes = message.as_bytes();
    let request = tonic::Request::new(SignGenericRequest {
      public_key: "ca09c8d185a2374f9e9e9b34dd1d11c6ee5a7341f00bb57104a7752094ee4757".to_string(),
      data: message_bytes.to_vec(),
      password: "Testacc1Testacc1".to_string(),
    });
    let response: tonic::Response<SignGenericResponse> = client.sign_generic(request).await?;
    let g1_affine = response_to_g1_affine(response.into_inner())?;
    let bls_g1_point = BlsG1Point::new(g1_affine);
    println!("Remote signature={:?}", bls_g1_point);
    let bls_key_pair = BlsKeyPair::new("11507468573326802429316131015508122374943382748905752594830347872745975341448".to_string()).unwrap();
    let public_key = bls_key_pair.public_key();
    println!("local public_key={:?}", public_key);
    let signature = bls_key_pair.sign_message(message_bytes);
    println!("local signature={:?}", signature);
    Ok(())
}

pub fn response_to_g1_affine(response: SignGenericResponse) -> Result<G1Affine,Box<dyn std::error::Error>> {
    let signature_bytes = response.signature.clone();
    println!("x={:?}", hex::encode(&signature_bytes[0..32]));
    println!("y={:?}", hex::encode(&signature_bytes[32..64]));
    Ok(G1Affine::new(Fq::from_be_bytes_mod_order(&signature_bytes[0..32]), Fq::from_be_bytes_mod_order(&signature_bytes[32..64])))
}