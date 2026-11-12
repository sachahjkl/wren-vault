//! Which saved URIs match a page. The helper has no Public Suffix List: the browser sends the registrable domain of
//! the page, and checks every returned row again with its own list (README.md, "Matching").

use url::Url;

/// How a saved URI is compared with the page (the item's match type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Domain,
    Host,
    StartsWith,
    Exact,
    RegularExpression,
    Never,
}

/// The page that a fill is for.
pub struct Page<'a> {
    pub url: &'a str,
    pub host: &'a str,
    /// The registrable domain of `host` ("" when it has none: an IP address, localhost, a public suffix).
    pub domain: &'a str,
}

/// The URI as the user saved it, made absolute: a URI without a scheme is read as https.
fn parse_saved(uri: &str) -> Option<Url> {
    let t = uri.trim();
    if t.is_empty() {
        return None;
    }
    if t.contains("://") {
        Url::parse(t).ok()
    } else {
        Url::parse(&format!("https://{t}")).ok()
    }
}

/// Whether a URI saved with rule `rule` matches the page, and the name of the rule that matched. Phase 1 knows
/// `Domain` and `Host`; the other rules match nothing.
pub fn matches(page: &Page, saved: &str, rule: Rule) -> Option<&'static str> {
    let Ok(frame) = Url::parse(page.url) else { return None };
    if frame.scheme() != "https" && frame.scheme() != "http" {
        return None;
    }
    let saved = parse_saved(saved)?;
    if saved.scheme() != "https" && saved.scheme() != "http" {
        return None;
    }
    // an item saved for https never goes to an http page
    if saved.scheme() == "https" && frame.scheme() == "http" {
        return None;
    }
    let saved_host = saved.host_str()?.to_ascii_lowercase();
    let host = page.host.to_ascii_lowercase();
    let same_host_and_port = || saved_host == host && saved.port_or_known_default() == frame.port_or_known_default();
    match rule {
        Rule::Domain if !page.domain.is_empty() => {
            let domain = page.domain.to_ascii_lowercase();
            let inside = saved_host == domain || saved_host.ends_with(&format!(".{domain}"));
            inside.then_some("domain")
        }
        Rule::Domain | Rule::Host => same_host_and_port().then_some("host"),
        Rule::StartsWith | Rule::Exact | Rule::RegularExpression | Rule::Never => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page<'a>(url: &'a str, host: &'a str, domain: &'a str) -> Page<'a> {
        Page { url, host, domain }
    }

    #[test]
    fn domain_matches_subdomains_of_the_registrable_domain() {
        let p = page("https://login.example.co.uk/a", "login.example.co.uk", "example.co.uk");
        assert_eq!(matches(&p, "https://example.co.uk", Rule::Domain), Some("domain"));
        assert_eq!(matches(&p, "https://www.example.co.uk/x", Rule::Domain), Some("domain"));
        assert_eq!(matches(&p, "example.co.uk", Rule::Domain), Some("domain"));
        assert_eq!(matches(&p, "https://other.co.uk", Rule::Domain), None);
        assert_eq!(matches(&p, "https://badexample.co.uk", Rule::Domain), None);
    }

    #[test]
    fn a_host_without_a_registrable_domain_uses_the_host_rule() {
        let p = page("http://127.0.0.1:8080/login", "127.0.0.1", "");
        assert_eq!(matches(&p, "http://127.0.0.1:8080", Rule::Domain), Some("host"));
        assert_eq!(matches(&p, "http://127.0.0.1:9090", Rule::Domain), None);
        let p = page("http://localhost:3000/", "localhost", "");
        assert_eq!(matches(&p, "http://localhost:3000/login", Rule::Host), Some("host"));
    }

    #[test]
    fn host_needs_the_same_port() {
        let p = page("https://a.example.com/", "a.example.com", "example.com");
        assert_eq!(matches(&p, "https://a.example.com:443", Rule::Host), Some("host"));
        assert_eq!(matches(&p, "https://a.example.com:8443", Rule::Host), None);
        assert_eq!(matches(&p, "https://b.example.com", Rule::Host), None);
    }

    #[test]
    fn an_https_item_does_not_go_to_an_http_page() {
        let p = page("http://example.com/", "example.com", "example.com");
        assert_eq!(matches(&p, "https://example.com", Rule::Domain), None);
        assert_eq!(matches(&p, "http://example.com", Rule::Domain), Some("domain"));
    }

    #[test]
    fn other_rules_match_nothing_in_phase_1() {
        let p = page("https://example.com/", "example.com", "example.com");
        for r in [Rule::StartsWith, Rule::Exact, Rule::RegularExpression, Rule::Never] {
            assert_eq!(matches(&p, "https://example.com/", r), None);
        }
    }

    #[test]
    fn non_web_schemes_match_nothing() {
        let p = page("https://example.com/", "example.com", "example.com");
        assert_eq!(matches(&p, "androidapp://com.example", Rule::Domain), None);
        let f = page("file:///tmp/a.html", "", "");
        assert_eq!(matches(&f, "https://example.com", Rule::Domain), None);
    }
}
