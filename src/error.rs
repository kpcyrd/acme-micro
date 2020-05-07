pub use anyhow::{Error, Result, Context, anyhow, bail};
pub use log::{debug, trace};
use crate::api::ApiProblem;

impl From<ApiProblem> for Error {
    fn from(x: ApiProblem) -> Error {
        anyhow!("{}", x)
    }
}
