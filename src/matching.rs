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
    /// The domains that the account makes equivalent to `domain` (its own groups and the server's global ones that
    /// hold it), lower case; empty when none.
    pub equivalent: &'a [String],
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

/// Whether `host` is `domain` or one of its subdomains (both lower case).
fn inside(host: &str, domain: &str) -> bool {
    !domain.is_empty() && (host == domain || host.ends_with(&format!(".{domain}")))
}

/// Whether a URI saved with rule `rule` matches the page, and the name of the rule that matched: "domain", "host",
/// "equivalent" (a domain that the account makes equivalent to the page's), "starts_with" or "exact".
/// `RegularExpression` and `Never` match nothing.
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
            if inside(&saved_host, &page.domain.to_ascii_lowercase()) {
                return Some("domain");
            }
            page.equivalent
                .iter()
                .any(|e| inside(&saved_host, &e.to_ascii_lowercase()))
                .then_some("equivalent")
        }
        Rule::Domain | Rule::Host => same_host_and_port().then_some("host"),
        // (both sides serialized by the URL standard: the browser compares the same strings)
        Rule::StartsWith => frame.as_str().starts_with(saved.as_str()).then_some("starts_with"),
        Rule::Exact => (frame.as_str() == saved.as_str()).then_some("exact"),
        Rule::RegularExpression | Rule::Never => None,
    }
}

/// The domains equivalent to `domain` in the account's groups: every domain of each group that holds it, except
/// `domain` itself. Lower case, without duplicates.
pub fn equivalent_of(groups: &[Vec<String>], domain: &str) -> Vec<String> {
    let domain = domain.to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    if domain.is_empty() {
        return out;
    }
    for g in groups {
        if !g.iter().any(|d| d.eq_ignore_ascii_case(&domain)) {
            continue;
        }
        for d in g {
            let d = d.trim().to_ascii_lowercase();
            if !d.is_empty() && d != domain && !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out
}

/// Whether one of an item's saved URIs (each with its rule) already covers `address`: a `save` adds the address to an
/// item only when none does, so that the item does not collect one URI per page of a site. Without a Public Suffix
/// List, a `Domain` URI covers the address when the address's host is the saved host or one of its subdomains. An
/// address that is no URL is covered only by the same text.
pub fn covered(address: &str, saved: &[(&str, Rule)]) -> bool {
    let address = address.trim();
    let Ok(url) = Url::parse(address) else {
        return saved.iter().any(|(s, _)| s.trim() == address);
    };
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    saved.iter().any(|(s, rule)| {
        if s.trim() == address {
            return true;
        }
        // (the saved host stands in for the registrable domain that the helper cannot compute)
        let domain = match (
            rule,
            parse_saved(s).and_then(|u| u.host_str().map(str::to_ascii_lowercase)),
        ) {
            (Rule::Domain, Some(h)) if inside(&host, &h) => h,
            _ => String::new(),
        };
        let page = Page {
            url: address,
            host: &host,
            domain: &domain,
            equivalent: &[],
        };
        matches(&page, s, *rule).is_some()
    })
}

/// Whether every word of `query` (split on white space, case aside) is in one of `texts`. An empty query matches.
pub fn search_matches(query: &str, texts: &[&str]) -> bool {
    let lower: Vec<String> = texts.iter().map(|t| t.to_lowercase()).collect();
    query.split_whitespace().all(|w| {
        let w = w.to_lowercase();
        lower.iter().any(|t| t.contains(&w))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page<'a>(url: &'a str, host: &'a str, domain: &'a str) -> Page<'a> {
        Page {
            url,
            host,
            domain,
            equivalent: &[],
        }
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
        assert_eq!(matches(&p, "https://example.com/", Rule::StartsWith), None);
    }

    #[test]
    fn starts_with_and_exact_compare_the_serialized_addresses() {
        let p = page("https://example.com/login?next=1", "example.com", "example.com");
        assert_eq!(
            matches(&p, "https://example.com/login", Rule::StartsWith),
            Some("starts_with")
        );
        assert_eq!(
            matches(&p, "https://EXAMPLE.com", Rule::StartsWith),
            Some("starts_with")
        );
        assert_eq!(matches(&p, "https://example.com/signup", Rule::StartsWith), None);
        assert_eq!(
            matches(&p, "https://example.com/login?next=1", Rule::Exact),
            Some("exact")
        );
        assert_eq!(matches(&p, "https://example.com/login", Rule::Exact), None);
    }

    #[test]
    fn never_and_regular_expressions_match_nothing() {
        let p = page("https://example.com/", "example.com", "example.com");
        for r in [Rule::RegularExpression, Rule::Never] {
            assert_eq!(matches(&p, "https://example.com/", r), None);
        }
    }

    #[test]
    fn equivalent_domains_extend_the_domain_rule_only() {
        let groups = vec![
            vec![
                "google.com".to_string(),
                "youtube.com".to_string(),
                "gmail.com".to_string(),
            ],
            vec!["example.org".to_string(), "example.net".to_string()],
        ];
        let eq = equivalent_of(&groups, "YouTube.com");
        assert_eq!(eq, vec!["google.com".to_string(), "gmail.com".to_string()]);
        assert!(equivalent_of(&groups, "other.com").is_empty());
        assert!(equivalent_of(&groups, "").is_empty());
        let p = Page {
            url: "https://www.youtube.com/",
            host: "www.youtube.com",
            domain: "youtube.com",
            equivalent: &eq,
        };
        assert_eq!(
            matches(&p, "https://accounts.google.com", Rule::Domain),
            Some("equivalent")
        );
        assert_eq!(matches(&p, "https://youtube.com", Rule::Domain), Some("domain"));
        assert_eq!(matches(&p, "https://accounts.google.com", Rule::Host), None);
        assert_eq!(matches(&p, "https://example.org", Rule::Domain), None);
    }

    #[test]
    fn non_web_schemes_match_nothing() {
        let p = page("https://example.com/", "example.com", "example.com");
        assert_eq!(matches(&p, "androidapp://com.example", Rule::Domain), None);
        let f = page("file:///tmp/a.html", "", "");
        assert_eq!(matches(&f, "https://example.com", Rule::Domain), None);
    }

    #[test]
    fn a_saved_uri_covers_the_pages_of_its_site() {
        let page = "https://login.example.com/signin?x=1";
        assert!(covered(page, &[("https://example.com", Rule::Domain)]));
        assert!(covered(page, &[("login.example.com", Rule::Domain)]));
        assert!(covered(page, &[("https://login.example.com/", Rule::Host)]));
        assert!(covered(page, &[("https://login.example.com/signin", Rule::StartsWith)]));
        assert!(!covered(page, &[("https://other.example.com", Rule::Domain)]));
        assert!(!covered(page, &[("https://example.com", Rule::Host)]));
        assert!(!covered(page, &[("https://login.example.com/", Rule::Never)]));
        assert!(!covered(page, &[]));
        assert!(covered("not a url", &[("not a url", Rule::Domain)]));
        assert!(!covered("not a url", &[("https://example.com", Rule::Domain)]));
    }

    #[test]
    fn a_search_needs_every_word_somewhere() {
        assert!(search_matches("", &["GitHub"]));
        assert!(search_matches("git me", &["GitHub", "me@example.com"]));
        assert!(!search_matches("git bank", &["GitHub", "me@example.com"]));
        assert!(search_matches("ÉCOLE", &["école.fr"]));
    }
}
