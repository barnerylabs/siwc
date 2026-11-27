//! The app's own look for the answer page: a stylesheet and a logo, checked
//! so that neither can add markup, a script or an outside resource.

use std::fmt;

use ring::digest;

use crate::error::{Error, ErrorKind};
use crate::protocol::base64url;

/// The longest stylesheet an app can add, in bytes. A page of two lines
/// needs a few hundred; a framework does not belong on it.
const MAX_STYLESHEET_LEN: usize = 16 * 1024;

/// The largest logo, in bytes: a 128-pixel PNG or a plain SVG fits.
const MAX_LOGO_LEN: usize = 32 * 1024;

/// The 8 bytes every PNG file starts with.
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// The app's look for the answer page: a stylesheet after the default one
/// and a logo above the heading. Both are optional.
///
/// Select `body` for page-wide styles. The remaining markup, class names
/// and default wording may change.
///
/// The page stays a single response without a script or an outside
/// resource. The stylesheet is allowed by its hash in the page's
/// `Content-Security-Policy`, the logo is inlined as a `data:` image, and
/// nothing else is allowed.
///
/// ```
/// use siwc::loopback::{LogoFormat, Page, Style};
///
/// let logo = b"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1 1\"/>";
/// let style = Style::default()
///     .stylesheet("body{background:#10243a;color:#f4f1ea}")?
///     .logo(LogoFormat::Svg, logo)?;
/// let page = Page::new(&siwc::AppName::new("Paste Perfect")?).with_style(style);
/// # drop(page);
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Style {
    stylesheet: Option<Stylesheet>,
    logo: Option<Logo>,
}

/// A checked stylesheet and the hash the policy allows it by.
#[derive(Clone, PartialEq, Eq)]
struct Stylesheet {
    text: String,
    hash: String,
}

/// Up to 16 KiB of text: `Debug` shows its length and hash instead.
impl fmt::Debug for Stylesheet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stylesheet")
            .field("len", &self.text.len())
            .field("hash", &self.hash)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Logo {
    format: LogoFormat,
    bytes: Vec<u8>,
}

/// Up to 32 KiB of image: `Debug` shows its format and length instead.
impl fmt::Debug for Logo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logo")
            .field("format", &self.format)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// The image formats a logo can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LogoFormat {
    /// PNG, `image/png`.
    Png,
    /// SVG, `image/svg+xml`. Browsers show an SVG image without running its
    /// scripts or loading anything it refers to.
    Svg,
}

impl LogoFormat {
    /// The media type in the `data:` URI.
    pub(super) fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Svg => "image/svg+xml",
        }
    }
}

impl Style {
    /// Adds `css` after the default stylesheet, so its rules win where both
    /// set the same property.
    ///
    /// Line breaks become line feeds, as the browser reads them before it
    /// checks the hash; nothing else is changed.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] for an empty stylesheet, one longer than
    /// 16 KiB, and one with `</` or a NUL character, which
    /// could end its `<style>` element or would be changed by the browser.
    pub fn stylesheet(mut self, css: &str) -> Result<Self, Error> {
        let refused = |reason| Err(Error::new(ErrorKind::InvalidInput, reason));
        if css.is_empty() {
            return refused("the stylesheet is empty");
        }
        if css.len() > MAX_STYLESHEET_LEN {
            return refused("the stylesheet is too long");
        }
        if css.contains("</") || css.contains('\0') {
            return refused("the stylesheet contains `</` or a NUL character");
        }
        let text = css.replace("\r\n", "\n").replace('\r', "\n");
        let hash = hash(&text);
        self.stylesheet = Some(Stylesheet { text, hash });
        Ok(self)
    }

    /// Shows `bytes` as the logo above the heading.
    ///
    /// The page describes the logo as decorative, since the heading names
    /// the app beside it.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] for an empty logo, one larger than
    /// 32 KiB, a PNG without the PNG signature and an SVG that is
    /// not UTF-8 text with an `<svg` element.
    pub fn logo(mut self, format: LogoFormat, bytes: &[u8]) -> Result<Self, Error> {
        let refused = |reason| Err(Error::new(ErrorKind::InvalidInput, reason));
        if bytes.is_empty() || bytes.len() > MAX_LOGO_LEN {
            return refused("the logo is empty or too large");
        }
        let fits = match format {
            LogoFormat::Png => bytes.starts_with(PNG_SIGNATURE),
            LogoFormat::Svg => str::from_utf8(bytes).is_ok_and(|text| text.contains("<svg")),
        };
        if !fits {
            return refused("the logo is not in the format it names");
        }
        self.logo = Some(Logo {
            format,
            bytes: bytes.to_vec(),
        });
        Ok(self)
    }

    /// The app's stylesheet as the page carries it.
    pub(super) fn stylesheet_text(&self) -> Option<&str> {
        self.stylesheet.as_ref().map(|sheet| sheet.text.as_str())
    }

    /// The hash of the app's stylesheet, for the policy.
    pub(super) fn stylesheet_hash(&self) -> Option<&str> {
        self.stylesheet.as_ref().map(|sheet| sheet.hash.as_str())
    }

    /// The logo's format and bytes.
    pub(super) fn logo_image(&self) -> Option<(LogoFormat, &[u8])> {
        self.logo
            .as_ref()
            .map(|logo| (logo.format, logo.bytes.as_slice()))
    }
}

/// Standard base64 of the SHA-256 of `css`, as a `Content-Security-Policy`
/// hash source names a style.
pub(super) fn hash(css: &str) -> String {
    base64url::encode_standard(digest::digest(&digest::SHA256, css.as_bytes()).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stylesheet_that_could_end_its_element_or_is_empty_or_too_long_is_refused() {
        let longest = "a".repeat(MAX_STYLESHEET_LEN);
        assert!(Style::default().stylesheet(&longest).is_ok());
        for css in [
            String::new(),
            "a".repeat(MAX_STYLESHEET_LEN + 1),
            "p{}</style><script>alert(1)</script>".to_owned(),
            "p{}</STYLE >".to_owned(),
            "p{content:\"</\"}".to_owned(),
            "p{}\0".to_owned(),
        ] {
            let error = Style::default().stylesheet(&css).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{css:?}");
        }
    }

    #[test]
    fn line_breaks_in_a_stylesheet_become_line_feeds_before_it_is_hashed() {
        let style = Style::default().stylesheet("a{}\r\nb{}\rc{}\n").unwrap();
        assert_eq!(style.stylesheet_text(), Some("a{}\nb{}\nc{}\n"));
        // printf 'a{}\nb{}\nc{}\n' | openssl dgst -sha256 -binary | base64
        assert_eq!(
            style.stylesheet_hash(),
            Some("J630wpjcfECE8H0nNITebJRE0aJaDAJkGxrHJisRFdY=")
        );
    }

    #[test]
    fn debug_shows_the_lengths_of_the_stylesheet_and_logo_not_their_content() {
        let mut png = PNG_SIGNATURE.to_vec();
        png.resize(MAX_LOGO_LEN, 7);
        let style = Style::default()
            .stylesheet("a{}")
            .unwrap()
            .logo(LogoFormat::Png, &png)
            .unwrap();
        assert_eq!(
            format!("{style:?}"),
            format!(
                "Style {{ stylesheet: Some(Stylesheet {{ len: 3, hash: {:?} }}), \
                 logo: Some(Logo {{ format: Png, len: 32768 }}) }}",
                hash("a{}")
            )
        );
    }

    #[test]
    fn a_logo_that_is_empty_too_large_or_not_its_format_is_refused() {
        let mut png = PNG_SIGNATURE.to_vec();
        png.resize(MAX_LOGO_LEN, 0);
        assert!(Style::default().logo(LogoFormat::Png, &png).is_ok());
        png.push(0);
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>";
        for (format, bytes) in [
            (LogoFormat::Png, &b""[..]),
            (LogoFormat::Png, &png[..]),
            (LogoFormat::Png, &svg[..]),
            (LogoFormat::Svg, PNG_SIGNATURE),
            (LogoFormat::Svg, b"<html></html>"),
            (LogoFormat::Svg, b"<svg \xff/>"),
        ] {
            let error = Style::default().logo(format, bytes).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{format:?}");
        }
    }
}
