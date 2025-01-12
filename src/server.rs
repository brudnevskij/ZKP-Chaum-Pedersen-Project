pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use num_bigint::{BigInt, BigUint};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use tonic::{transport::Server, Code, Request, Response, Status};
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};
use zkp_auth_project::ZKP;

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    // registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    // auth
    pub r1: BigUint,
    pub r2: BigUint,
    // verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let request = request.into_inner();
        println!("Request: {:?}", request);
        let user_name = request.user;
        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        let mut user_info = UserInfo::default();
        user_info.user_name = user_name.clone();
        user_info.y1 = y1;
        user_info.y2 = y2;

        let mut user_info_storage = &mut self.user_info.lock().unwrap();
        user_info_storage.insert(user_name, user_info);

        Ok(Response::new(RegisterResponse {}))
    }
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let request = request.into_inner();
        print!("Request: {:?}", request);
        let user_name = request.user;
        let mut user_info_storage = &mut self.user_info.lock().unwrap();

        if let Some(user_info) = user_info_storage.get_mut(&user_name) {
            let (_, _, _, q) = ZKP::get_constants();
            let c = ZKP::generate_random_below(&q);
            let auth_id = ZKP::generate_random_string(12);

            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);
            user_info.c = c.clone();

            let auth_id_storage = &mut self.auth_id_to_user.lock().unwrap();
            auth_id_storage.insert(auth_id.clone(), user_info.user_name.clone());

            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }))
        } else {
            Err(Status::new(Code::NotFound, "User not found".to_string()))
        }
    }
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Request: {:?}", request);
        let request = request.into_inner();

        let auth_id = request.auth_id;
        let mut auth_info_storage = &mut self.auth_id_to_user.lock().unwrap();

        if let Some(user_name) = auth_info_storage.get_mut(&auth_id) {
            let mut user_info_storage = &mut self.user_info.lock().unwrap();
            let user = user_info_storage.get_mut(user_name).unwrap();

            let s = request.s;
            let (alpha, beta, p, q) = ZKP::get_constants();
            let zkp = ZKP { p, q, alpha, beta };
            let verification = zkp.verify(
                &user.r1,
                &user.r2,
                &user.y1,
                &user.y2,
                &BigUint::from_bytes_be(&s),
                &user.c,
            );
            if verification {
                let session_id = ZKP::generate_random_string(12);
                Ok(Response::new(AuthenticationAnswerResponse { session_id }))
            } else {
                Err(Status::new(Code::NotFound, "Bad solution".to_string()))
            }
        } else {
            Err(Status::new(Code::NotFound, "Auth_id not found".to_string()))
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();

    println!("Starting server on {} address", addr);
    let auth_impl = AuthImpl::default();
    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("Could not convert address"))
        .await
        .unwrap();
}
