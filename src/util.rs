use base64::Engine;
use serde::de::DeserializeOwned;

use crate::error::*;
use crate::req::req_safe_read_body;

pub(crate) fn base64url<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(input)
}

pub(crate) fn read_json<T: DeserializeOwned>(res: ureq::Response) -> Result<T> {
    let res_body = req_safe_read_body(res);
    debug!("{}", res_body);
    Ok(serde_json::from_str(&res_body)?)
}
