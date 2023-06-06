use base64::engine::Engine;
use lazy_static::lazy_static;
use serde::de::DeserializeOwned;

use crate::error::*;
use crate::req::req_safe_read_body;

lazy_static! {
    static ref BASE64_CONFIG: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE;
}

pub(crate) fn base64url<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    BASE64_CONFIG.encode(input)
}

pub(crate) fn read_json<T: DeserializeOwned>(res: ureq::Response) -> Result<T> {
    let res_body = req_safe_read_body(res);
    debug!("{}", res_body);
    Ok(serde_json::from_str(&res_body)?)
}
