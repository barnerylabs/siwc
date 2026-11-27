//! The wording the provider's interface guidelines ask for.
//!
//! ```
//! use siwc::plan::wording;
//!
//! let button = wording::SIGN_IN;
//! assert_eq!(button, "Continue with ChatGPT");
//! ```

/// The label of the sign-in button.
pub const SIGN_IN: &str = "Continue with ChatGPT";

/// A dismissible confirmation, shown once after the first sign-in that
/// grants plan use and not after later sign-ins.
pub const WELCOME: &str = "You're using your ChatGPT plan";

/// The note shown near the composer or the model picker while requests use
/// the plan.
pub const USING_PLAN: &str = "Using ChatGPT plan";

/// The label of the link to [`MANAGE_USAGE_URL`](super::MANAGE_USAGE_URL).
pub const MANAGE_USAGE: &str = "Manage usage";
