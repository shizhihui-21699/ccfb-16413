"""Policy: what counts as trusted in *this* organisation.

Everything here is configuration, not code logic.  A real deployment loads it
from the mail gateway's config store; the defaults below are a defensible
starting point for a mid-size enterprise whose collaboration stack is
Microsoft 365 + Zoom.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def _domains(block: str) -> set[str]:
    return {line.strip().lower() for line in block.split() if line.strip() and not line.strip().startswith("#")}


# ---------------------------------------------------------------------------
# The organisation itself
# ---------------------------------------------------------------------------

@dataclass
class Organisation:
    name: str = "Example Corp"
    # Domains the org actually owns; mail from these is internal.
    domains: set[str] = field(default_factory=lambda: _domains("""
        example.com example.org example.net
    """))
    # Brands we must not let anyone imitate.  Tokens are matched against host
    # labels after homoglyph folding.
    own_brands: dict[str, set[str]] = field(default_factory=lambda: {
        "examplecorp": {"examplecorp", "example-corp", "example corp"},
        "example": {"example"},
    })
    # Peoples' names are too generic to combosquat on; keep the list minimal.
    extra_brand_tokens: dict[str, set[str]] = field(default_factory=dict)

    def is_internal_domain(self, host: str, *, registrable_domain) -> bool:
        host = host.lower().strip(".")
        if not host:
            return False
        if host in self.domains:
            return True
        reg = registrable_domain(host)
        return reg in self.domains


# ---------------------------------------------------------------------------
# Recognised video-conferencing vendors
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Vendor:
    key: str
    display: str
    # Real registrable domains for this vendor.  Only these may hold a
    # one-click "join" affordance in a rewritten invite.
    domains: frozenset[str]
    # Hosts that serve the actual meeting UI.
    meeting_hosts: tuple[str, ...] = ()
    # Tokens that, when found in title/description/location/URL, suggest the
    # invite is *about* this vendor.
    tokens: tuple[str, ...] = ()

    def owns(self, host: str, *, registrable_domain) -> bool:
        reg = registrable_domain(host)
        return reg in self.domains


VENDORS: tuple[Vendor, ...] = (
    Vendor(
        key="teams",
        display="Microsoft Teams",
        domains=frozenset({"microsoft.com", "microsoftonline.com", "office.com",
                           "office365.com", "live.com", "teams.microsoft.com"}),
        meeting_hosts=("teams.microsoft.com", "teams.live.com"),
        tokens=("teams", "microsoft teams", "ms teams"),
    ),
    Vendor(
        key="zoom",
        display="Zoom",
        domains=frozenset({"zoom.us", "zoom.com", "zoomgov.com", "zoom.us.com"}),
        meeting_hosts=("zoom.us", "us02web.zoom.us", "us04web.zoom.us",
                       "us05web.zoom.us", "us06web.zoom.us"),
        tokens=("zoom", "zoom meeting", "zoomgov"),
    ),
    Vendor(
        key="webex",
        display="Webex",
        domains=frozenset({"webex.com", "webex.co", "ciscospark.com", "wbx2.com"}),
        meeting_hosts=("webex.com",),
        tokens=("webex", "cisco webex"),
    ),
    Vendor(
        key="google_meet",
        display="Google Meet",
        domains=frozenset({"meet.google.com", "google.com", "googleusercontent.com"}),
        meeting_hosts=("meet.google.com",),
        tokens=("google meet", "meet.google", "hangouts", "google hangout"),
    ),
    Vendor(
        key="gotomeeting",
        display="GoTo Meeting",
        domains=frozenset({"gotomeeting.com", "goto.com", "goto meeting.com"}),
        meeting_hosts=("meet.goto.com", "global.gotomeeting.com"),
        tokens=("gotomeeting", "go to meeting", "goto meeting", "gotomeet"),
    ),
    Vendor(
        key="bluejeans",
        display="BlueJeans",
        domains=frozenset({"bluejeans.com"}),
        meeting_hosts=("bluejeans.com",),
        tokens=("bluejeans", "blue jeans"),
    ),
    Vendor(
        key="ringcentral",
        display="RingCentral",
        domains=frozenset({"ringcentral.com", "ringcentral meetings.com"}),
        meeting_hosts=("meetings.ringcentral.com", "v.ringcentral.com"),
        tokens=("ringcentral",),
    ),
    Vendor(
        key="feishu",
        display="Feishu / Lark",
        domains=frozenset({"feishu.cn", "larksuite.com", "feishu.net"}),
        meeting_hosts=("vc.feishu.cn", "meetings.feishu.cn"),
        tokens=("feishu", "lark", "飞书"),
    ),
    Vendor(
        key="dingtalk",
        display="DingTalk",
        domains=frozenset({"dingtalk.com", "dingtalk.cn"}),
        meeting_hosts=("meeting.dingtalk.com",),
        tokens=("dingtalk", "dingding", "钉钉"),
    ),
    Vendor(
        key="tencent_meeting",
        display="Tencent Meeting",
        domains=frozenset({"tencent.com", "meeting.tencent.com", "qq.com"}),
        meeting_hosts=("meeting.tencent.com",),
        tokens=("tencent meeting", "voov", "腾讯会议", "vooV meeting"),
    ),
    Vendor(
        key="whereby",
        display="Whereby",
        domains=frozenset({"whereby.com"}),
        meeting_hosts=("whereby.com",),
        tokens=("whereby",),
    ),
    Vendor(
        key="jitsi",
        display="Jitsi",
        domains=frozenset({"jitsi.org", "jit.si"}),
        meeting_hosts=("meet.jit.si",),
        tokens=("jitsi", "meet.jit.si"),
    ),
    Vendor(
        key="chime",
        display="Amazon Chime",
        domains=frozenset({"chime.aws", "aws.amazon.com", "amazon.com"}),
        meeting_hosts=("app.chime.aws",),
        tokens=("chime", "amazon chime"),
    ),
)

VENDOR_BY_KEY: dict[str, Vendor] = {v.key: v for v in VENDORS}

# Brand tokens the risk engine considers imitable even when the invite never
# names them (a fake "Microsoft login" page is suspicious regardless).
GLOBAL_BRAND_TOKENS: dict[str, set[str]] = {
    "microsoft": {"microsoft", "msft", "office365", "office 365", "outlook"},
    "office": {"office", "office365", "outlook", "onedrive", "sharepoint"},
    "teams": {"teams", "msteams", "ms teams"},
    "zoom": {"zoom", "zoomgov", "zoomus"},
    "webex": {"webex", "ciscowebex"},
    "google": {"google", "gmail", "gsuite", "workspace", "google meet"},
    "apple": {"apple", "icloud"},
    "amazon": {"amazon", "aws", "chime"},
    "dropbox": {"dropbox"},
    "docusign": {"docusign", "docusign"},
    "adobe": {"adobe", "adobesign"},
    "okta": {"okta"},
    "ping": {"pingidentity", "pingone"},
    "salesforce": {"salesforce"},
    "slack": {"slack"},
    "tencent": {"tencent", "qq", "wechat", "weixin"},
    "aliyun": {"aliyun", "alibaba", "alipay", "dingtalk"},
    "baidu": {"baidu"},
    "jd": {"jd", "jingdong"},
    "hr": {"workday", "servicenow", "concur"},
    "bank": {"paypal", "stripe", "hsbc", "citi", "chase", "bankofamerica"},
}

# Providers whose users get a per-tenant subdomain; the *suffix* is the brand,
# so ``contoso.sharepoint.com`` is not a Microsoft-branded subdomain abuse.
TENANT_SUFFIXES: frozenset[str] = frozenset({
    "sharepoint.com", "sharepoint.cn", "onmicrosoft.com", "azurewebsites.net",
    "googleusercontent.com", "appspot.com", "github.io", "gitlab.io",
    "herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev",
    "notion.site", "wixsite.com", "blogspot.com", "myshopify.com",
    "s3.amazonaws.com", "cloudfront.net", "blob.core.windows.net",
})


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

# Free consumer mailboxes: legitimate for a prospect, but never for a vendor's
# security notice or a colleague.
FREE_MAIL_DOMAINS: frozenset[str] = frozenset("""
    gmail.com googlemail.com outlook.com hotmail.com live.com msn.com
    yahoo.com yahoo.co.uk ymail.com rocketmail.com
    aol.com icloud.com me.com mac.com proton.me protonmail.com
    gmx.com gmx.net mail.com zoho.com yandex.com yandex.ru
    qq.com 163.com 126.com sina.com sina.cn sohu.com yeah.net
    aliyun.com foxmail.com 139.com wo.cn 21cn.com tom.com
    naver.com daum.net hanmail.net web.de freenet.de
    tutanota.com tutamail.com mail.ru inbox.ru list.ru bk.ru
    rediffmail.com hushmail.com fastmail.com hey.com
    disposablemail.com mailinator.com guerrillamail.com 10minutemail.com
    tempmail.com temp-mail.org throwawaymail.com yopmail.com
""".split())

# Registrable domains used for bulk/one-shot mail (subset; matched on rdomain).
DISPOSABLE_SUFFIXES: frozenset[str] = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "dispostable.com", "trashmail.com",
    "maildrop.cc", "getnada.com", "emailondeck.com", "spamgourmet.com",
    "mytemp.email", "burnermail.io", "mailnesia.com", "fakeinbox.com",
})

# TLDs with very high abuse density relative to their legitimate use.
HIGH_RISK_TLDS: frozenset[str] = frozenset("""
    zip mov top xyz tk ml ga cf gq buzz cc ws icu cyou rest monster sbs
    cfd click link live loan work men gift review country kim party racing
    date download stream trade win bid fail quest cam su fit lol mom
    beauty hair skin make up vip wang ren xin club online site space website
    shop store tech life world today press host fun cyber
""".split())

# Very common legitimate TLDs that should not be penalised at all.
BENIGN_TLDS: frozenset[str] = frozenset("""
    com net org edu gov mil int io co ai app dev cloud us uk de fr jp cn
    com.cn ca au nl se no fi dk ch at be it es pt pl cz sk hu ro bg gr tr
    il in sg hk tw kr nz ie za br mx ar cl pe info biz name pro museum aero
    news blog design email
""".split())


def tld_of(host: str) -> str:
    host = host.lower().strip(".")
    if not host or "." not in host:
        return ""
    return host.rsplit(".", 1)[-1]


def build_brand_tokens(org: Organisation) -> dict[str, set[str]]:
    """Merge global vendor brands, vendor tokens, and the org's own brands."""
    tokens: dict[str, set[str]] = {k: set(v) for k, v in GLOBAL_BRAND_TOKENS.items()}
    for vendor in VENDORS:
        tokens.setdefault(vendor.key, set()).update(vendor.tokens)
    for brand, words in org.own_brands.items():
        tokens.setdefault(brand, set()).update(words)
    for brand, words in org.extra_brand_tokens.items():
        tokens.setdefault(brand, set()).update(words)
    return tokens


# Brands matched with edit-distance tolerance are only the long, distinctive
# ones; short tokens like "jd" or "qq" would match half the internet.
STRICT_MATCH_BRANDS: frozenset[str] = frozenset({
    "microsoft", "office", "teams", "zoom", "webex", "google", "apple",
    "amazon", "dropbox", "docusign", "adobe", "okta", "salesforce", "slack",
    "tencent", "aliyun", "baidu", "workday", "servicenow", "paypal", "stripe",
})


@dataclass
class Policy:
    org: Organisation = field(default_factory=Organisation)
    vendors: tuple[Vendor, ...] = VENDORS
    free_mail_domains: frozenset[str] = FREE_MAIL_DOMAINS
    disposable_suffixes: frozenset[str] = DISPOSABLE_SUFFIXES
    high_risk_tlds: frozenset[str] = HIGH_RISK_TLDS
    benign_tlds: frozenset[str] = BENIGN_TLDS
    brand_tokens: dict[str, set[str]] = field(init=False)
    # A calendar whose ORGANIZER is one of these is machine-generated by a
    # platform, so we trust its join links a little more.
    platform_organizer_domains: frozenset[str] = frozenset({
        "calendar.google.com", "calendar-notification.google.com",
        "zoom.us", "webex.com", "microsoft.com",
    })

    def __post_init__(self) -> None:
        self.brand_tokens = build_brand_tokens(self.org)

    def vendor_by_key(self, key: str) -> Vendor | None:
        return VENDOR_BY_KEY.get(key)

    def vendor_for_host(self, host: str, *, registrable_domain) -> Vendor | None:
        for vendor in self.vendors:
            if vendor.owns(host, registrable_domain=registrable_domain):
                return vendor
        return None

    def vendor_mentioned(self, text: str) -> list[Vendor]:
        lowered = (text or "").lower()
        hits = []
        for vendor in self.vendors:
            if any(token in lowered for token in vendor.tokens):
                hits.append(vendor)
        return hits
