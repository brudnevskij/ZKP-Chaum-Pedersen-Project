use crate::zkp_auth::auth_client::AuthClient;
use crate::zkp_auth::{
    AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest,
};
use num_bigint::BigUint;
use std::io::stdin;
use zkp_auth_project::ZKP;

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

#[tokio::main]
async fn main() {
    let mut client = AuthClient::connect("http://localhost:50051")
        .await
        .expect("Auth client failed");
    println!("Connected to the server");

    println!("Please provide username");
    let mut buff = String::new();
    stdin().read_line(&mut buff).expect("Failed to read line");
    let username = buff.trim().to_string();
    buff.clear();

    println!("Please provide password");
    stdin().read_line(&mut buff).expect("Failed to read line");
    let password = BigUint::from_bytes_be(buff.trim().as_bytes());

    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP { p, q, alpha, beta };

    let y1 = ZKP::exponentiate(&zkp.alpha, &password, &zkp.p);
    let y2 = ZKP::exponentiate(&zkp.beta, &password, &zkp.p);

    let register_request = RegisterRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    let _response = client
        .register(register_request)
        .await
        .expect("register failed");

    let k = ZKP::generate_random_below(&zkp.q);
    let r1 = ZKP::exponentiate(&zkp.alpha, &k, &zkp.p);
    let r2 = ZKP::exponentiate(&zkp.beta, &k, &zkp.p);

    let challenge_request = AuthenticationChallengeRequest {
        user: username.clone(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };
    let response = client
        .create_authentication_challenge(challenge_request)
        .await
        .expect("authentication challenge failed");
    let response = response.into_inner();
    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    buff.clear();
    println!("Please provide password");
    stdin().read_line(&mut buff).expect("Failed to read line");
    let password = BigUint::from_bytes_be(buff.trim().as_bytes());
    let s = zkp.solve(&k, &c, &password);
    let auth_request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };
    let response = client
        .verify_authentication(auth_request)
        .await
        .expect("authentication failed");
    println!("You logged in {:?}", response.into_inner().session_id);
}
