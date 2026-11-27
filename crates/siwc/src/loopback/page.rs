//! The page the browser tab shows once the sign-in is over.

use crate::app::AppName;
use crate::protocol::base64url;

use super::style::Style;

/// The page's default style, which an app's [`Style`] can add to. Changing
/// it means changing [`STYLE_HASH`]; a test keeps the two together.
pub(super) const STYLE: &str = ":root{color-scheme:light dark}body{margin:0;font-family:system-ui,-apple-system,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;line-height:1.5}main{max-width:32rem;margin:15vh auto 0;padding:0 1.5rem}h1{font-size:1.5rem;font-weight:600;margin:0 0 .75rem}p{margin:0}.logo{display:block;height:4rem;width:auto;max-width:100%;margin:0 0 1rem}";

/// Standard base64 of the SHA-256 of [`STYLE`], for the
/// `Content-Security-Policy` that allows exactly this style.
pub(super) const STYLE_HASH: &str = "Fv+1UseQ8TY1wzxBa317TOSHt7NRh+v/9aVXxgdtDxQ=";

/// A `Content-Security-Policy` that allows the default style, the app's
/// stylesheet by its hash, inline images when there is a logo, and nothing
/// else.
pub(super) fn policy(stylesheet_hash: Option<&str>, logo: bool) -> String {
    let stylesheet = stylesheet_hash
        .map(|hash| format!(" 'sha256-{hash}'"))
        .unwrap_or_default();
    let images = if logo { "img-src data:; " } else { "" };
    format!(
        "default-src 'none'; style-src 'sha256-{STYLE_HASH}'{stylesheet}; {images}\
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
}

/// How the sign-in ended, as the user should read it in the browser tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Answer {
    /// The user is signed in and the app may use their ChatGPT plan.
    SignedIn,
    /// The user is signed in, but did not allow use of their ChatGPT plan.
    SignedInPlanUseOff,
    /// The user declined in the browser.
    Declined,
    /// The sign-in did not complete.
    Failed,
}

/// The app's name, the texts of the answer page and its look.
///
/// ```
/// use siwc::loopback::{Page, Text, Texts};
///
/// let app = siwc::AppName::new("Paste Perfect")?;
/// let english = Page::new(&app);
///
/// let mut texts = Texts::default();
/// texts.lang = "de".to_owned();
/// texts.signed_in = Text::new("Angemeldet bei {app}", "Du kannst diesen Tab schließen.");
/// let german = Page::with_texts(&app, texts);
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    app: AppName,
    texts: Texts,
    style: Style,
}

impl Page {
    /// A page with the English default [`Texts`].
    #[must_use]
    pub fn new(app: &AppName) -> Self {
        Self::with_texts(app, Texts::default())
    }

    /// A page with the app's own texts, for example in the user's language.
    #[must_use]
    pub fn with_texts(app: &AppName, texts: Texts) -> Self {
        Self {
            app: app.clone(),
            texts,
            style: Style::default(),
        }
    }

    /// The same page in the app's own [`Style`].
    #[must_use]
    pub fn with_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// The `Content-Security-Policy` of this page.
    pub(super) fn policy(&self) -> String {
        policy(
            self.style.stylesheet_hash(),
            self.style.logo_image().is_some(),
        )
    }

    /// The text for how the sign-in ended.
    pub(super) fn text(&self, answer: Answer) -> &Text {
        match answer {
            Answer::SignedIn => &self.texts.signed_in,
            Answer::SignedInPlanUseOff => &self.texts.signed_in_plan_use_off,
            Answer::Declined => &self.texts.declined,
            Answer::Failed => &self.texts.failed,
        }
    }

    /// The text for a start link that is not, or no longer, valid.
    pub(super) fn link_expired(&self) -> &Text {
        &self.texts.link_expired
    }

    /// A complete HTML document showing `text`.
    pub(super) fn html(&self, text: &Text) -> String {
        let app = escape(self.app.as_str());
        let fill = |template: &str| escape(template).replace("{app}", &app);
        let heading = fill(&text.heading);
        let detail = fill(&text.detail);
        let lang = escape(&self.texts.lang);
        // Checked when the style was made: no `</` that could end the
        // element, so the text goes in as it is and keeps its hash.
        let stylesheet = self
            .style
            .stylesheet_text()
            .map(|css| format!("<style>{css}</style>\n"))
            .unwrap_or_default();
        // Base64 needs no escaping in a quoted attribute.
        let logo = self
            .style
            .logo_image()
            .map(|(format, bytes)| {
                let media_type = format.media_type();
                let data = base64url::encode_standard(bytes);
                format!("<img class=\"logo\" src=\"data:{media_type};base64,{data}\" alt=\"\">\n")
            })
            .unwrap_or_default();
        format!(
            "<!DOCTYPE html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <title>{heading}</title>\n<style>{STYLE}</style>\n{stylesheet}</head>\n<body>\n\
             <main>\n{logo}<h1>{heading}</h1>\n<p>{detail}</p>\n</main>\n</body>\n</html>\n"
        )
    }
}

/// The texts of the answer page, one per way a sign-in can end.
///
/// They are plain text, never HTML: every character is shown as written.
/// `{app}` stands for the app's name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Texts {
    /// The language of the texts as a BCP 47 tag, such as `en` or `de`, so
    /// that screen readers pronounce the page correctly.
    pub lang: String,
    /// Signed in, with use of the ChatGPT plan.
    pub signed_in: Text,
    /// Signed in, without use of the ChatGPT plan.
    pub signed_in_plan_use_off: Text,
    /// The user declined in the browser.
    pub declined: Text,
    /// The sign-in did not complete.
    pub failed: Text,
    /// A start link that is unknown or belongs to a wait that is over.
    pub link_expired: Text,
}

impl Default for Texts {
    /// The English texts.
    fn default() -> Self {
        Self {
            lang: "en".to_owned(),
            signed_in: Text::new(
                "Signed in to {app}",
                "You can close this tab and return to {app}.",
            ),
            signed_in_plan_use_off: Text::new(
                "Signed in to {app}",
                "ChatGPT plan use is not enabled for {app}. You can enable it in {app}.",
            ),
            declined: Text::new(
                "Sign-in cancelled",
                "Nothing was shared with {app}. You can close this tab.",
            ),
            failed: Text::new("Sign-in did not complete", "Return to {app} and try again."),
            link_expired: Text::new(
                "This sign-in link is no longer valid",
                "Return to {app} and start again.",
            ),
        }
    }
}

/// A heading and one paragraph below it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Text {
    /// The page title and its main heading.
    pub heading: String,
    /// The sentence below the heading.
    pub detail: String,
}

impl Text {
    /// Builds a [`Text`] from its heading and detail paragraph.
    #[must_use]
    pub fn new(heading: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            heading: heading.into(),
            detail: detail.into(),
        }
    }
}

/// Escapes text for HTML element content and quoted attribute values.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::super::style::{LogoFormat, hash};
    use super::*;

    #[test]
    fn the_style_hash_is_the_hash_of_the_style() {
        assert_eq!(hash(STYLE), STYLE_HASH);
    }

    #[test]
    fn markup_characters_in_texts_and_the_app_name_are_escaped() {
        let app = AppName::new("Tom & \"Jerry\" <b>").unwrap();
        let page = Page::new(&app);
        let html = page.html(page.text(Answer::Failed));
        assert!(html.contains("Return to Tom &amp; &quot;Jerry&quot; &lt;b&gt; and try again."));

        let texts = Texts {
            failed: Text::new("<i>'{app}'</i>", "Return to {app} and try again."),
            ..Texts::default()
        };
        let page = Page::with_texts(&app, texts);
        let html = page.html(page.text(Answer::Failed));
        assert!(
            html.contains("&lt;i&gt;&#39;Tom &amp; &quot;Jerry&quot; &lt;b&gt;&#39;&lt;/i&gt;")
        );
        assert!(!html.contains("<i>") && !html.contains("<b>"));
    }

    #[test]
    fn the_language_of_custom_texts_is_the_language_of_the_page() {
        let app = AppName::new("Paste Perfect").unwrap();
        let texts = Texts {
            lang: "de".to_owned(),
            ..Texts::default()
        };
        let page = Page::with_texts(&app, texts);
        assert!(
            page.html(page.text(Answer::SignedIn))
                .contains("<html lang=\"de\">")
        );

        let texts = Texts {
            lang: "\"><script>".to_owned(),
            ..Texts::default()
        };
        let page = Page::with_texts(&app, texts);
        assert!(
            page.html(page.text(Answer::SignedIn))
                .contains("<html lang=\"&quot;&gt;&lt;script&gt;\">")
        );
    }

    #[test]
    fn an_app_name_that_looks_like_the_placeholder_is_not_expanded_again() {
        let app = AppName::new("{app}").unwrap();
        let page = Page::new(&app);
        assert!(
            page.html(page.text(Answer::Failed))
                .contains("Return to {app} and try again.")
        );
    }

    #[test]
    fn the_page_has_one_style_no_script_and_no_external_resource() {
        let app = AppName::new("Paste Perfect").unwrap();
        let page = Page::new(&app);
        let html = page.html(page.text(Answer::SignedIn));
        assert!(html.starts_with("<!DOCTYPE html>\n<html lang=\"en\">"));
        assert!(html.contains("<meta charset=\"utf-8\">"));
        assert!(html.contains("<meta name=\"viewport\""));
        assert!(html.contains("<title>Signed in to Paste Perfect</title>"));
        assert!(html.contains("<h1>Signed in to Paste Perfect</h1>"));
        assert!(html.contains("<p>You can close this tab and return to Paste Perfect.</p>"));
        assert_eq!(html.matches("<style>").count(), 1);
        assert!(html.contains(&format!("<style>{STYLE}</style>")));
        for absent in ["<script", "<img", "src=", "href=", "url(", "@import"] {
            assert!(!html.contains(absent), "{absent}");
        }
        assert_eq!(
            page.policy(),
            format!(
                "default-src 'none'; style-src 'sha256-{STYLE_HASH}'; \
                 base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )
        );
    }

    #[test]
    fn an_apps_stylesheet_follows_the_default_and_the_policy_allows_both_by_hash() {
        let app = AppName::new("Paste Perfect").unwrap();
        let css = "body{background:#10243a;color:#f4f1ea}";
        let style = Style::default().stylesheet(css).unwrap();
        let page = Page::new(&app).with_style(style);
        let html = page.html(page.text(Answer::SignedIn));
        assert!(html.contains(&format!(
            "<style>{STYLE}</style>\n<style>{css}</style>\n</head>"
        )));
        // printf '%s' 'body{background:#10243a;color:#f4f1ea}' | openssl dgst -sha256 -binary | base64
        let app_hash = "Bnxxx8qRhWxNFhHDhIS5B5bQzoEJXR/1mngRdcj3SbI=";
        assert_eq!(
            page.policy(),
            format!(
                "default-src 'none'; style-src 'sha256-{STYLE_HASH}' 'sha256-{app_hash}'; \
                 base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )
        );
    }

    #[test]
    fn a_logo_is_an_inline_image_and_only_then_may_the_page_show_data_images() {
        let app = AppName::new("Paste Perfect").unwrap();
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>";
        for (format, bytes, src) in [
            (
                LogoFormat::Png,
                &png[..],
                "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==",
            ),
            (
                LogoFormat::Svg,
                &svg[..],
                "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=",
            ),
        ] {
            let style = Style::default().logo(format, bytes).unwrap();
            let page = Page::new(&app).with_style(style);
            let html = page.html(page.text(Answer::SignedIn));
            assert!(
                html.contains(&format!(
                    "<main>\n<img class=\"logo\" src=\"{src}\" alt=\"\">\n<h1>"
                )),
                "{format:?}"
            );
            assert_eq!(html.matches("<style>").count(), 1);
            assert_eq!(
                page.policy(),
                format!(
                    "default-src 'none'; style-src 'sha256-{STYLE_HASH}'; img-src data:; \
                     base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                )
            );
        }
    }
}
