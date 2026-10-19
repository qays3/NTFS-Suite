use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::server::state::AppState;
use crate::vault::security_store::{self, SecurityDescriptor};

#[derive(Deserialize)]
pub struct SecureLookup {
    #[serde(default)]
    pub security_id: i64,
    #[serde(default)]
    pub entry: i64,
}

// Resolve the security descriptor behind a record. Accepts a security id
// directly, or an MFT entry whose security id is read from the records table.
pub async fn lookup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SecureLookup>,
) -> Result<Json<Option<SecurityDescriptor>>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;

    let mut sid = req.security_id;
    if sid == 0 && req.entry != 0 {
        sid = conn
            .query_row(
                "SELECT security_id FROM records WHERE entry = ?1 LIMIT 1",
                [req.entry],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0);
    }
    if sid == 0 {
        return Ok(Json(None));
    }
    let desc = security_store::get(conn, sid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(desc))
}
