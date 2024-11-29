use cerberus_api::{
    client::SignerClient,
    SignGenericRequest,
    SignGenericResponse,
};
use ark_bn254::{Fq,g1::G1Affine};
use ark_ff::PrimeField;
use eigen_crypto_bls::BlsG1Point;
#[tokio::main]
async fn main() -> Result<(),Box<dyn std::error::Error>> {
    let mut client: SignerClient<tonic::transport::Channel> = SignerClient::connect("http://[::1]:50051").await?;
    let message = "Hello, world!";
    let message_bytes = message.as_bytes();
    let request = tonic::Request::new(SignGenericRequest {
      public_key: "bls_public_key".to_string(),
      data: message_bytes.to_vec(),
      password: "password".to_string(),
    });
    let response: tonic::Response<SignGenericResponse> = client.sign_generic(request).await?;
    let g1_affine = response_to_g1_affine(response.into_inner())?;
    let bls_g1_point = BlsG1Point::new(g1_affine);
    println!("bls_g1_point={:?}", bls_g1_point);
    Ok(())
}

fn response_to_g1_affine(response: SignGenericResponse) -> Result<G1Affine, Box<dyn std::error::Error>> {
    let signature_bytes = response.signature.clone();
    let hex_string = hex::encode(&signature_bytes);
    let bytes = hex::decode(&hex_string).expect("Failed to decode hex");
    let x_bytes = &bytes[0..32];
    let y_bytes = &bytes[32..64];
    let fqx = Fq::from_be_bytes_mod_order(x_bytes);
    let fqy = Fq::from_be_bytes_mod_order(y_bytes);
    Ok(G1Affine::new(fqx, fqy))
}