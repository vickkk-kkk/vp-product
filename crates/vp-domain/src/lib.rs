//! Pure product contracts. No network, filesystem, OS SDK or upstream runtime.
//! Parsing a model is not capability certification or permission to apply it.
#![forbid(unsafe_code)]

pub mod capability;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod management_secrets;
pub mod node;
pub mod operation;
pub mod runtime;
pub mod secrets;
pub mod subscription;
pub mod version;

pub use capability::*;
pub use envelope::*;
pub use error::*;
pub use ids::*;
pub use management_secrets::*;
pub use node::*;
pub use operation::*;
pub use runtime::*;
pub use secrets::*;
pub use subscription::*;
pub use version::*;
