//! Synthetic user profiles for [`FakeProvider`](super::FakeProvider).

/// A synthetic user identity and permission set approved at a
/// [`FakeProvider`](super::FakeProvider).
///
/// By default, `FakeUser::new(email)` grants ChatGPT plan use and a renewable
/// refresh token, marks `email` as verified, and derives a stable subject from
/// `email`.
///
/// ```
/// use siwc::testing::FakeUser;
///
/// let user = FakeUser::new("owner@example.invalid")
///     .name("Alex Example")
///     .without_plan_use();
/// # drop(user);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeUser {
    pub(super) subject: String,
    pub(super) email: Option<String>,
    pub(super) email_verified: bool,
    pub(super) name: Option<String>,
    pub(super) picture: Option<String>,
    pub(super) plan_use: bool,
    pub(super) renewable: bool,
}

impl FakeUser {
    /// Synthetic user identified by `email`, with plan use and refresh enabled.
    #[must_use]
    pub fn new(email: &str) -> Self {
        let sanitized: String = email
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    char::from(b.to_ascii_lowercase())
                } else {
                    '-'
                }
            })
            .take(48)
            .collect();
        let subject = if sanitized.is_empty() {
            "user-synthetic-default".to_owned()
        } else {
            format!("user-synthetic-{sanitized}")
        };
        Self {
            subject,
            email: Some(email.to_owned()),
            email_verified: true,
            name: None,
            picture: None,
            plan_use: true,
            renewable: true,
        }
    }

    /// Overrides the verified `sub` claim.
    #[must_use]
    pub fn subject(mut self, subject: &str) -> Self {
        self.subject = subject.to_owned();
        self
    }

    /// Sets the optional display `name` claim.
    #[must_use]
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_owned());
        self
    }

    /// Omits the `email` claim from issued ID tokens.
    #[must_use]
    pub fn without_email(mut self) -> Self {
        self.email = None;
        self.email_verified = false;
        self
    }

    /// Marks the `email` claim as unverified (`email_verified: false`).
    #[must_use]
    pub fn unverified_email(mut self) -> Self {
        self.email_verified = false;
        self
    }

    /// Sets the optional `picture` HTTPS URL claim.
    #[must_use]
    pub fn picture(mut self, url: &str) -> Self {
        self.picture = Some(url.to_owned());
        self
    }

    /// Grants identity scopes without `chatgpt.tokens.use.direct`, until a
    /// consent re-authorization (`prompt=consent`) upgrades the grant.
    #[must_use]
    pub fn without_plan_use(mut self) -> Self {
        self.plan_use = false;
        self
    }

    /// Omits `offline_access` and issues no refresh token.
    #[must_use]
    pub fn without_refresh_token(mut self) -> Self {
        self.renewable = false;
        self
    }
}
