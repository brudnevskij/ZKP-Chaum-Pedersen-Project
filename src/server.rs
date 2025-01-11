pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use num_bigint::{BigInt, BigUint};
use tonic::{transport::Server, Code, Request, Response, Status};
use tonic::codegen::ok;
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};
use zkp_auth_project::ZKP;

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String,UserInfo>>,
    pub auth_id_to_user: Mutex<HashMap<String,String>>
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
        print!("Request: {:?}", request);
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
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            let (_,_,_,q) = ZKP::get_constants();
            let c  = ZKP::generate_random_below(&q);
            let auth_id = "skdjfsk".to_string();

            let auth_id_storage = &mut self.auth_id_to_user.lock().unwrap();
            auth_id_storage.insert(auth_id.clone(), user_info.user_name.clone());

            Ok(Response::new(AuthenticationChallengeResponse{auth_id, c: c.to_bytes_be()}))
        } else {
            Err(Status::new(Code::NotFound, "User not found".to_string()))
        }
    }
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        todo!()
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
