use std::error::Error;

use axum::routing::{get, post};
use axum::Router;
use axum_login::tower_sessions::{Expiry, SessionManagerLayer};
use axum_login::{login_required, AuthManagerLayerBuilder};
use tower_http::cors::{Any, CorsLayer};
use tower_sessions::cookie::time::Duration;
use tower_sessions::MemoryStore;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use axum::async_trait;
use axum_login::{AuthUser, AuthnBackend, UserId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct UserAuth {
    pub id: i32,
    pub username: String,
    password: String,
}

impl std::fmt::Debug for UserAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

impl AuthUser for UserAuth {
    type Id = i32;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.password.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Backend {}

#[async_trait]
impl AuthnBackend for Backend {
    type User = UserAuth;
    type Credentials = Credentials;
    type Error = std::convert::Infallible;

    async fn authenticate(
        &self,
        _creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // assuming verification OK

        let userauth = Self::User {
            id: 1,
            username: "username".to_owned(),
            password: "pw".to_owned(),
        };

        Ok(Some(userauth))
    }

    async fn get_user(&self, _id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        // assuming getting user OK

        let userauth = Self::User {
            id: 1,
            username: "username".to_owned(),
            password: "pw".to_owned(),
        };

        Ok(Some(userauth))
    }
}

type AuthSession = axum_login::AuthSession<Backend>;

pub fn secret_route() -> Router<()> {
    Router::new().route("/api/secret", get(self::get::only_logged_get))
}

mod get {
    use axum_login::{
        axum::{http::StatusCode, response::IntoResponse},
        tracing,
    };

    use super::*;

    pub async fn only_logged_get(auth_session: AuthSession) -> impl IntoResponse {
        tracing::error!("In protected handler");
        match auth_session.user {
            Some(user) => {
                println!("I got secret only if user is logged in: {:?}", user);
                StatusCode::OK.into_response()
            }
            None => {
                println!("Protected API, UNAUTHORIZED");
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
        .into_response()
    }
}

pub fn login_route() -> Router<()> {
    Router::new().route("/login", post(self::post::login))
}

mod post {
    use axum_login::axum::{http::StatusCode, response::IntoResponse};

    use crate::{AuthSession, Credentials};
    use axum::Form;

    pub async fn login(
        mut auth_session: AuthSession,
        Form(creds): Form<Credentials>,
    ) -> impl IntoResponse {
        let user = match auth_session.authenticate(creds.clone()).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                println!("invalid creds");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        if auth_session.login(&user).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        println!("Successfully logged in as {}", user.username);

        StatusCode::OK.into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axum_login=trace,tower_sessions=trace,sqlx=warn,tower_http=trace".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));

    let backend = Backend::default();
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    let app = secret_route()
        .route_layer(login_required!(Backend, login_url = "/login"))
        .merge(login_route())
        .layer(auth_layer)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Couldn't open a TCP socket");

    println!(
        "🚀 Server started successfully on {}",
        listener.local_addr().unwrap()
    );
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
