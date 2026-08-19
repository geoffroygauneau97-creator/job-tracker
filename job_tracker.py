#!/usr/bin/env python3
"""Scan a Gmail inbox for job-application emails and summarize them.

First run opens a browser for Google OAuth login (using credentials.json in
this folder) and caches the resulting token in token.json for future runs.

Usage:
    python job_tracker.py
    python job_tracker.py --max-results 500 --oldest-first
    python job_tracker.py --query 'newer_than:6m subject:(interview OR offer)'
"""

import argparse
import html
import re
import sys
import webbrowser
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

import truststore

# Some antivirus/corporate software (e.g. Avast Web Shield) intercepts HTTPS
# traffic and re-signs it with a locally-installed root CA. Those root certs
# sometimes fail Python's strict OpenSSL validation even though Windows and
# browsers accept them fine, so delegate verification to the OS trust store.
truststore.inject_into_ssl()

# Windows consoles are often cp1252, but email subjects can contain arbitrary
# Unicode (curly quotes, trademark symbols, etc.) - don't crash on those.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCRIPT_DIR = Path(__file__).resolve().parent
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CREDENTIALS_FILE = SCRIPT_DIR / "credentials.json"
TOKEN_FILE = SCRIPT_DIR / "token.json"
REPORT_FILE = SCRIPT_DIR / "report.html"

# status -> (badge css class, dot color token, sentence-case label)
STATUS_META = {
    "Applied":   ("badge-applied",   "--info-blue",       "Applied"),
    "Interview": ("badge-interview", "--status-warning",  "Interview"),
    "Offer":     ("badge-offer",     "--status-good",      "Offer"),
    "Rejected":  ("badge-rejected",  "--status-critical",  "Rejected"),
}
SUMMARY_STATUSES = ["Applied", "Interview", "Offer", "Rejected"]

DEFAULT_QUERY = (
    "in:inbox newer_than:1y "
    '(subject:("your application" OR "application for" OR "applying to" OR '
    '"thank you for applying" OR interview OR "job offer" OR '
    '"offer letter" OR "pleased to offer" OR candidacy OR "hiring process") '
    "OR from:(greenhouse OR lever OR myworkdayjobs OR icims OR "
    "smartrecruiters OR taleo OR ashbyhq OR jobvite OR bamboohr OR breezy.hr OR "
    "recruitee OR workable) "
    # Rejection-only emails often don't repeat "application"/"interview" in
    # the subject at all (e.g. subject is just "Update from Acme Corp"), and
    # plenty of companies send them from their own domain, not a listed ATS -
    # so also match on body text for phrasing that's unambiguously a job
    # rejection wherever it appears in the message, not just the subject.
    'OR "other candidates" OR "other applicants" OR "move forward with other" '
    'OR "moving forward with other" OR "pursue other candidates" OR '
    '"proceed with other applicants" OR "will not be moving forward" OR '
    '"not be moving forward with your application" OR "position has been filled" '
    'OR "will not be proceeding with your" OR "decided not to move forward" OR '
    '"elected to move forward with other" OR "thank you for your interest in" OR '
    '"thank you for taking the time to apply") '
    '-subject:("job alert" OR "jobs for you" OR "new jobs" OR "recommended jobs" OR '
    '"and your next steps" OR "weekly download" OR "magazine interview" OR '
    '"founder interview" OR "mistakes to avoid" OR "nail your" OR "reveals the truth" OR '
    '"has a job offer for you" OR '
    '"one-time-passcode" OR "one time passcode" OR "demographic survey" OR '
    'édition OR digest OR newsletter OR unsubscribe OR tips OR "how to" OR '
    "card OR statement OR payment OR order OR shipped OR receipt OR "
    "invoice OR discount OR promo OR reward OR points OR flight OR itinerary OR "
    'subscription OR "sign in" OR security) '
    "-from:(discover.com OR wellsfargo.com OR citi.com OR americanexpress.com OR "
    "chase.com OR capitalone.com OR bankofamerica.com)"
)

# ATS/job-platform domains -> human-readable platform name. Used both to
# recognize these senders and, as a last resort, to fill the Company/Platform
# column with the platform's own name when the actual employer can't be
# determined from anywhere in the email - every row should show *something*.
ATS_DOMAINS = {
    "greenhouse.io": "Greenhouse", "greenhouse-mail.io": "Greenhouse",
    "lever.co": "Lever", "myworkdayjobs.com": "Workday", "workday.com": "Workday",
    "icims.com": "iCIMS", "smartrecruiters.com": "SmartRecruiters", "taleo.net": "Taleo",
    "ashbyhq.com": "Ashby", "jobvite.com": "Jobvite", "bamboohr.com": "BambooHR",
    "breezy.hr": "Breezy HR", "recruitee.com": "Recruitee", "workable.com": "Workable",
    "linkedin.com": "LinkedIn", "indeed.com": "Indeed", "ziprecruiter.com": "ZipRecruiter",
    "successfactors.com": "SuccessFactors", "clickboarding.com": "Clickboarding",
}

GENERIC_SENDER_WORDS = re.compile(
    r"\b(careers?|recruiting|talent(\s+acquisition)?|human\s+resources|hr|"
    r"jobs?|hiring|people\s+team|notifications?|no[.\-]?reply|do\s*not\s*reply|team|"
    r"greenhouse|lever|workday|icims|smartrecruiters|taleo|ashby(hq)?|jobvite|"
    r"bamboohr|breezy(\.hr)?|recruitee|workable|applicant\s*tracking\s*system|"
    r"mail|system|email)\b",
    re.IGNORECASE,
)

# Sender display names that survive cleaning but are still not a company name
# (ATS product handles, placeholder addresses, etc. observed in real inboxes).
JUNK_SENDER_TOKENS = {
    "myworkday", "yourcareer", "recruitmail", "applicantemails", "vssend",
    "invalidemail", "osgtool", "mcview", "greenhousemail", "noreply",
    "donotreply", "applicanttrackingsystem", "jobvitesystem",
}

# (status_label, keywords) — checked in order, first match wins.
STATUS_RULES = [
    ("Rejected", [
        "unfortunately", "not moving forward", "not selected", "not be selected",
        "other candidates", "other applicants", "decided not to proceed",
        "will not be moving forward", "pursue other candidates",
        "will not be proceeding", "position has been filled",
        "have decided not to", "not able to move forward", "elected not to move forward",
        "decided to move forward with other candidates", "after careful consideration",
        "thank you for taking the time to apply", "chosen to proceed with other applicants",
        "will not be extending an offer", "unable to offer you a position",
        "not the right fit", "not a match for this",
    ]),
    ("Offer", [
        "pleased to offer you", "offer letter", "excited to offer you",
        "extend you an offer", "extend an offer of employment",
        "formal offer of employment", "offer of employment", "welcome to the team",
    ]),
    ("Interview", [
        "interview", "phone screen", "next steps", "schedule a call",
        "schedule some time", "would like to speak", "meet with", "hiring manager",
        "technical assessment", "coding challenge", "take-home",
    ]),
    ("Applied", [
        "thank you for applying", "application received", "we've received your application",
        "we have received your application", "your application", "application was sent",
        "successfully applied", "confirm your application", "applying to",
        "thanks for applying",
    ]),
]

# Shared "stop here" boundary for company-name captures: real punctuation,
# a connector word, a standalone dash separator, an @ or ( (calendar invites
# and req-numbers embed an email/ID right after the name), or end of string.
_TAIL = r"(?:[!.,@(]|\s+(?:for|with|dated)\b|\s+[-–—]\s|\s*$)"

COMPANY_PATTERNS = [
    r"thank you for applying to ([A-Z][\w&.,' -]*?)" + _TAIL,
    # LinkedIn-style "Your application to <Role> at <Company>" - grab only
    # the part after " at " here, before the generic pattern below can grab
    # the whole "<Role> at <Company>" blob as if it were all one company.
    r"application to [\w\s/&(),.-]+? at ([A-Z][\w&.,' -]*?)" + _TAIL,
    r"your application to ([A-Z][\w&.,' -]*?)" + _TAIL,
    r"application (?:for .*? )?at ([A-Z][\w&.,' -]*?)" + _TAIL,
    r"interview (?:request |invitation )?(?:from|with) ([A-Z][\w&.,' -]*?)" + _TAIL,
    r"your application (?:for .*? )?(?:to|with) ([A-Z][\w&.,' -]*?)" + _TAIL,
    r"your application was sent to ([A-Z][\w&.,' -]*?)" + _TAIL,
    r"thanks?(?:\s+you)? for your interest in ([A-Z][\w&.,' -]*?)" + _TAIL,
    r"([A-Z][\w&.,' -]*?) has received your application",
    r"update on your ([A-Z][\w&.,' -]*?) application",
    r"^([A-Z][\w&.,' -]{1,40}?)\s*[:\-]\s*(?:interview|application|update|offer)",
    # Last-resort generic fallback - only reached once every specific
    # phrasing above has failed to match.
    r"\bat ([A-Z][\w&.,' -]*?)" + _TAIL,
]

ROLE_PATTERNS = [
    r"for the ([\w\s/&-]+?) (?:position|role) at",
    # "for (the) position/role of X" must be tried before the generic
    # "applying/application for X" patterns below: the capture group there
    # requires at least one character, so it can never stop exactly at the
    # start of the word "position"/"role" - it always eats into it first,
    # which would otherwise leak "position of" into the captured role.
    r"applying for (?:the )?(?:position|role) of ([\w\s/&-]+?)(?:[!.,]|\s+at\s|\s*$)",
    r"application for (?:the )?(?:position|role) of ([\w\s/&-]+?)(?:[!.,]|\s+at\s|\s*$)",
    r"applying for (?:the )?([\w\s/&-]+?)(?:\s+position\b|\s+role\b|[!.,]|\s+at\s|\s*$)",
    r"application for (?:the )?([\w\s/&-]+?)(?:\s+position\b|\s+role\b|[!.,]|\s+at\s|\s*$)",
    # LinkedIn-style "Your application to <Role> at <Company>" - the role
    # half. Requires " at [A-Z]" right after, so it never fires on plain
    # "your application to <Company>" subjects (no trailing "at" there).
    r"application to ([\w\s/&-]+?) at [A-Z]",
    # "Your recent job application for <Role> - <req #>" - very common ATS
    # subject line; the role has no company mixed in here.
    r"job application for ([\w\s/&(),.-]+?)(?:\s+dated\b|[!.,]|\s*$)",
    r"application\s*[-–—]\s*([\w\s/&-]+?)\s*$",
    r"role of ([\w\s/&-]+?)(?:[!.,]|\s+at\s|\s*$)",
    r"position of ([\w\s/&-]+?)(?:[!.,]|\s+at\s|\s*$)",
]

# Filler words that signal we've captured a sentence fragment, not a job
# title (e.g. "taking the time to apply to our..." or "...has been received").
ROLE_FILLER_WORDS = {
    "thank", "thanks", "taking", "time", "please", "we", "you", "your",
    "us", "congratulations", "regarding", "please note", "team",
    "considering",
    "has", "have", "had", "was", "were", "is", "are", "been", "being",
    "received", "submitted", "confirmed", "complete", "completed",
}

# Common job-title words. A 2-word all-capitalized capture that contains
# none of these almost always means we captured the applicant's own name
# (e.g. an "Application - <Name>" subject line), not a role.
ROLE_TITLE_HINTS = re.compile(
    r"engineer|manager|specialist|analyst|developer|coordinator|technician|"
    r"director|lead|associate|intern|scientist|architect|consultant|"
    r"representative|executive|officer|administrator|designer|agent|planner|"
    r"technologist|supervisor|assistant|strategist|researcher|programmer|"
    r"engineering|sales|marketing|product|project|support|operations|"
    r"design|process|manufacturing|quality|systems|solutions",
    re.IGNORECASE,
)


def get_gmail_service():
    """Authenticate with Gmail, opening a browser on first run, and return a service client."""
    if not CREDENTIALS_FILE.exists():
        sys.exit(
            f"Missing {CREDENTIALS_FILE.name} in {SCRIPT_DIR}. "
            "Download an OAuth client (Desktop app) from Google Cloud Console "
            "and save it there."
        )

    creds = None
    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
            creds = flow.run_local_server(port=0)
        TOKEN_FILE.write_text(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def fetch_messages(service, query, max_results):
    """Return a list of {subject, from, date, snippet} dicts matching the query."""
    ids = []
    page_token = None
    while len(ids) < max_results:
        resp = service.users().messages().list(
            userId="me",
            q=query,
            pageToken=page_token,
            maxResults=min(100, max_results - len(ids)),
        ).execute()
        ids.extend(m["id"] for m in resp.get("messages", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    results = []
    for msg_id in ids:
        try:
            msg = service.users().messages().get(
                userId="me",
                id=msg_id,
                format="metadata",
                metadataHeaders=["Subject", "From", "Date"],
            ).execute()
        except HttpError as e:
            print(f"warning: failed to fetch message {msg_id}: {e}", file=sys.stderr)
            continue

        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
        results.append({
            "subject": headers.get("Subject", ""),
            "from": headers.get("From", ""),
            "date": headers.get("Date", ""),
            "snippet": msg.get("snippet", ""),
        })
    return results


def classify_status(text):
    lowered = text.lower().replace("’", "'").replace("‘", "'")
    for label, keywords in STATUS_RULES:
        if any(kw in lowered for kw in keywords):
            return label
    # No confident signal either way - "Applied" is the safest default,
    # since every email in this report came from a genuine application.
    return "Applied"


def extract_first_match(patterns, text, require_capitalized=False):
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            value = strip_trailing_greeting(m.group(1).strip(" -:,."))
            if not value:
                continue
            # re.IGNORECASE also loosens the pattern's own [A-Z] anchor, so a
            # lowercase word (e.g. "us" in "...interview with us") can slip
            # through - re-check the actual captured text, not the pattern.
            if require_capitalized and not value[0].isupper():
                continue
            return value
    return None


def strip_trailing_greeting(value):
    """Drop a personalized ", <Name>" sign-off some ATS templates append,
    e.g. "Insight Global, Geoffroy" -> "Insight Global"."""
    return re.sub(r",\s*[A-Z][a-z]+\s*$", "", value).strip(" -:,.")


def clean_sender_name(name):
    # ATS senders often format the display name as "<Company> @ <platform>"
    # (e.g. "Exponent Inc. @ icims") - that "@" is a separator, not an email
    # address, so drop it (and the platform name after it) before the
    # generic-word pass and the "looks like an email" rejection below.
    name = re.sub(r"\s+@\s+\S*\s*$", "", name)
    cleaned = GENERIC_SENDER_WORDS.sub("", name)
    cleaned = re.sub(r"[|\-,]+", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return None
    if "@" in cleaned:
        return None
    if re.sub(r"[^a-z0-9]", "", cleaned.lower()) in JUNK_SENDER_TOKENS:
        return None
    return cleaned


# Singular job-title nouns. A company-candidate string that *ends* in one of
# these (singular) reads as a bare role, e.g. "Corrosion Engineer" - whereas
# the plural form is a normal company-name suffix, e.g. "Bala Consulting
# Engineers" or "MPR Associates". Only the singular form is rejected.
ROLE_NOUN_SINGULAR = {
    "engineer", "manager", "specialist", "analyst", "developer", "coordinator",
    "technician", "director", "scientist", "architect", "consultant",
    "representative", "executive", "officer", "administrator", "designer",
    "agent", "planner", "technologist", "supervisor", "assistant",
    "strategist", "researcher", "programmer", "lead", "associate", "intern",
}


def looks_like_role(text):
    words = re.findall(r"[A-Za-z]+", text)
    return bool(words) and words[-1].lower() in ROLE_NOUN_SINGULAR


# A captured company candidate that *starts* with one of these is really the
# start of a sentence/greeting the generic "^X - update" pattern latched
# onto, e.g. "Thank You for Your Application - Update on Your Job Status".
COMPANY_GREETING_WORDS = {"thank", "thanks", "dear", "hi", "hello", "hey", "greetings"}


def find_company_candidate(patterns, text):
    """Try each company pattern in order, skipping any match that reads like
    a bare job title rather than a company name. Returns (company, role_hint)
    - role_hint carries the best skipped role-shaped match, if any, so the
    caller can reuse it as the role instead of throwing it away."""
    role_hint = None
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            continue
        value = strip_trailing_greeting(m.group(1).strip(" -:,."))
        if not value or not value[0].isupper():
            continue
        if value.split()[0].lower() in COMPANY_GREETING_WORDS:
            continue
        if looks_like_role(value):
            if role_hint is None:
                role_hint = value
            continue
        return value, role_hint
    return None, role_hint


def extract_company(subject, snippet, sender_header):
    company, role_hint = find_company_candidate(COMPANY_PATTERNS, subject)
    if not company:
        snippet_company, snippet_role_hint = find_company_candidate(COMPANY_PATTERNS, snippet)
        company = snippet_company
        role_hint = role_hint or snippet_role_hint
    if company:
        return company, False, role_hint

    display_name, email_addr = parseaddr(sender_header)
    if display_name and "@" not in display_name:
        cleaned = clean_sender_name(display_name)
        if cleaned:
            return cleaned, True, role_hint

    domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
    parts = domain.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    if domain and root_domain not in ATS_DOMAINS:
        company = parts[-2].capitalize() if len(parts) >= 2 else domain
        return company, True, role_hint

    # Last resort: the actual employer couldn't be pinned down anywhere in
    # the email, but every row still needs *something* in Company/Platform -
    # fall back to the job platform's own name (e.g. "Greenhouse", "iCIMS").
    if root_domain in ATS_DOMAINS:
        return ATS_DOMAINS[root_domain], True, role_hint

    return "", True, role_hint


ROLE_STOPWORDS = {
    "the", "a", "an", "this", "that", "for", "with", "your", "our", "of",
    "and", "to", "in", "on", "at", "it", "us", "we", "you",
    "position", "role", "job", "opportunity",
}


def clean_role_text(role):
    if not role:
        return ""
    role = re.sub(r"^(the|a|an)\s+", "", role, flags=re.IGNORECASE)
    role = re.sub(r"\s+(position|role)$", "", role, flags=re.IGNORECASE)
    role = role.strip()
    if not role or role.lower() in ROLE_STOPWORDS or len(role) <= 2:
        return ""
    words = role.split()
    # A real job title (plus an optional trailing "- <req #>") is short.
    # Anything longer is almost always a captured sentence fragment (e.g.
    # "taking the time to apply to our...").
    if len(words) > 8:
        return ""
    if any(w.strip(".,!?").lower() in ROLE_FILLER_WORDS for w in words):
        return ""
    if (
        len(words) == 2
        and all(re.fullmatch(r"[A-Z][a-z'.-]+", w) for w in words)
        and not ROLE_TITLE_HINTS.search(role)
    ):
        return ""
    return role


def extract_role(subject, snippet):
    role = extract_first_match(ROLE_PATTERNS, subject) or extract_first_match(ROLE_PATTERNS, snippet)
    return clean_role_text(role)


def parse_date(date_header):
    try:
        return parsedate_to_datetime(date_header)
    except (TypeError, ValueError):
        return None


def build_entries(messages):
    entries = []
    for msg in messages:
        subject = msg["subject"]
        snippet = msg["snippet"]
        status = classify_status(subject + " " + snippet)
        company, guessed_company, role_hint = extract_company(subject, snippet, msg["from"])
        role = extract_role(subject, snippet) or clean_role_text(role_hint)
        dt = parse_date(msg["date"])
        entries.append({
            "date": dt,
            "status": status,
            "company": company,
            "role": role,
            "guessed_company": guessed_company,
            "subject": subject,
        })
    return entries


def _merge_interview_cluster(cluster):
    best_role = next((e["role"] for e in cluster if e["role"]), cluster[-1]["role"])
    latest = max(cluster, key=lambda e: e["date"])
    return {
        "date": latest["date"],
        "status": "Interview",
        "company": latest["company"],
        "role": best_role,
        "guessed_company": latest["guessed_company"],
        "subject": latest["subject"],
        "merge_count": len(cluster),
    }


def dedupe_interviews(entries, window_days=45):
    """A single interview process generates several emails (invite,
    confirmation, day-before/hour-before reminders). Collapse same-company
    Interview emails that fall within window_days of each other into one
    entry so counts reflect distinct interview processes, not raw emails."""
    interviews = [e for e in entries if e["status"] == "Interview" and e["date"] is not None and e["company"]]
    others = [e for e in entries if not (e["status"] == "Interview" and e["date"] is not None and e["company"])]

    by_company = {}
    for e in interviews:
        key = re.sub(r"[^a-z0-9]", "", e["company"].lower())
        by_company.setdefault(key, []).append(e)

    merged = []
    for group in by_company.values():
        group.sort(key=lambda e: e["date"])
        cluster = [group[0]]
        for e in group[1:]:
            if (e["date"] - cluster[-1]["date"]).days <= window_days:
                cluster.append(e)
            else:
                merged.append(_merge_interview_cluster(cluster))
                cluster = [e]
        merged.append(_merge_interview_cluster(cluster))

    return others + merged


def render_html(entries, oldest_first):
    entries = [e for e in entries if e["date"] is not None]
    entries.sort(key=lambda e: e["date"], reverse=not oldest_first)

    counts = {status: 0 for status in STATUS_META}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    total = len(entries)

    stat_cards = "\n".join(
        f'''      <div class="card">
        <div class="card-label"><span class="dot" style="background:var({STATUS_META[status][1]})"></span>{html.escape(STATUS_META[status][2])}</div>
        <div class="card-value">{counts.get(status, 0)}</div>
      </div>'''
        for status in SUMMARY_STATUSES
    )

    # Simple horizontal bar chart, one bar per status, reusing the same
    # status colors/labels as the stat cards above. Each bar carries its own
    # text label + numeric value, so status is never color-alone.
    max_count = max((counts.get(s, 0) for s in SUMMARY_STATUSES), default=0) or 1
    chart_rows = "\n".join(
        f'''      <div class="chart-row">
        <span class="chart-label">{html.escape(STATUS_META[status][2])}</span>
        <div class="chart-track"><div class="chart-fill" style="width:{counts.get(status, 0) / max_count * 100:.1f}%; background:var({STATUS_META[status][1]})"></div></div>
        <span class="chart-value">{counts.get(status, 0)}</span>
      </div>'''
        for status in SUMMARY_STATUSES
    )

    rows = []
    any_merged = False
    for e in entries:
        date_str = e["date"].strftime("%Y-%m-%d")
        css_class, _, label = STATUS_META[e["status"]]
        subject_title = html.escape(e["subject"], quote=True)

        if e["company"]:
            company_html = html.escape(e["company"])
            if e["guessed_company"]:
                company_html += ' <span class="hint" title="Inferred from the sender - may be the job platform rather than the exact employer">*</span>'
        else:
            company_html = '<span class="hint" title="Could not be confidently determined">&mdash;</span>'

        merge_count = e.get("merge_count", 1)
        if merge_count > 1:
            any_merged = True
            company_html += (
                f' <span class="hint" title="{merge_count} related emails (invite/confirmation/reminders) '
                f'grouped into this one interview">&times;{merge_count}</span>'
            )

        role_html = (
            html.escape(e["role"]) if e["role"]
            else '<span class="hint" title="Could not be confidently determined">&mdash;</span>'
        )

        rows.append(f'''      <tr>
        <td class="date" data-sort="{date_str}">{date_str}</td>
        <td class="company" title="{subject_title}" data-sort="{html.escape(e["company"], quote=True)}">{company_html}</td>
        <td class="role" title="{subject_title}" data-sort="{html.escape(e["role"], quote=True)}">{role_html}</td>
        <td data-sort="{html.escape(label, quote=True)}"><span class="badge {css_class}">{html.escape(label)}</span></td>
      </tr>''')

    now = datetime.now()
    generated_at = f"{now:%B} {now.day}, {now:%Y} at {(now.hour - 1) % 12 + 1}:{now:%M %p}"

    role_blank_count = sum(1 for e in entries if not e["role"])
    company_blank_count = sum(1 for e in entries if not e["company"])
    notes = []
    if role_blank_count:
        notes.append(
            f'{role_blank_count} entr{"y" if role_blank_count == 1 else "ies"} '
            f'{"has" if role_blank_count == 1 else "have"} no role shown because the email never states one — '
            "hover a row to see the original email subject."
        )
    if company_blank_count:
        notes.append(
            f'{company_blank_count} entr{"y" if company_blank_count == 1 else "ies"} '
            f'{"has" if company_blank_count == 1 else "have"} no company/platform shown because neither could be '
            "determined — hover a row to see the original email subject."
        )
    if any_merged:
        notes.append(
            'Interview counts are grouped by company — repeated emails for the same interview '
            '(invite, confirmation, reminders) count once. Look for &times;N next to a company name.'
        )
    unclear_note = "".join(f'<p class="muted-note">{n}</p>' for n in notes)

    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Geoff's Job Application Tracker</title>
<style>
  :root {{
    color-scheme: light;
    --surface-1:      #fcfcfb;
    --page-plane:     #f9f9f7;
    --text-primary:   #0b0b0b;
    --text-secondary: #52514e;
    --text-muted:     #898781;
    --gridline:       #e1e0d9;
    --border:         rgba(11,11,11,0.10);
    --info-blue:      #2a78d6;
    --status-good:     #0ca30c;
    --status-warning:  #fab219;
    --status-critical: #d03b3b;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      color-scheme: dark;
      --surface-1:      #1a1a19;
      --page-plane:     #0d0d0d;
      --text-primary:   #ffffff;
      --text-secondary: #c3c2b7;
      --text-muted:     #898781;
      --gridline:       #2c2c2a;
      --border:         rgba(255,255,255,0.10);
      --info-blue:      #3987e5;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--page-plane);
    color: var(--text-primary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 24px 16px 48px; }}
  header h1 {{ font-size: clamp(1.4rem, 4vw, 1.8rem); margin: 0 0 4px; }}
  header p {{ margin: 0; color: var(--text-secondary); font-size: 0.9rem; }}

  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin: 24px 0;
  }}
  .card {{
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }}
  .card.total {{ grid-column: 1 / -1; }}
  .card-label {{
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 0.82rem;
    font-weight: 600;
    color: var(--text-secondary);
  }}
  .dot {{ width: 9px; height: 9px; border-radius: 50%; flex: none; }}
  .card-value {{ font-size: 1.9rem; font-weight: 700; line-height: 1; }}
  .card.total .card-value {{ font-size: 3rem; }}
  .muted-note {{ color: var(--text-muted); font-size: 0.85rem; margin: 8px 2px 0; }}

  .chart-card {{
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px 20px 20px;
    margin: 16px 0;
  }}
  .chart-card h2 {{
    margin: 0 0 14px;
    font-size: 0.82rem;
    font-weight: 600;
    color: var(--text-secondary);
  }}
  .chart-row {{ display: flex; align-items: center; gap: 10px; }}
  .chart-row + .chart-row {{ margin-top: 10px; }}
  .chart-label {{ width: 72px; flex: none; font-size: 0.82rem; color: var(--text-secondary); }}
  .chart-track {{ flex: 1; height: 14px; background: var(--page-plane); border-radius: 7px; overflow: hidden; }}
  .chart-fill {{ height: 100%; border-radius: 7px; }}
  .chart-value {{
    width: 38px;
    flex: none;
    text-align: right;
    font-variant-numeric: tabular-nums;
    font-weight: 600;
    font-size: 0.85rem;
  }}

  .search-box {{
    width: 100%;
    margin: 16px 0 4px;
    padding: 10px 14px;
    border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--surface-1);
    color: var(--text-primary);
    font-size: 0.9rem;
    font-family: inherit;
  }}
  .search-box:focus {{ outline: 2px solid var(--info-blue); outline-offset: -1px; }}

  .table-wrap {{
    margin-top: 20px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: auto;
    max-height: 75vh;
  }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.88rem; }}
  thead th {{
    position: sticky;
    top: 0;
    background: var(--surface-1);
    text-align: left;
    padding: 12px 14px;
    font-size: 0.78rem;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--gridline);
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
  }}
  thead th:hover {{ color: var(--text-primary); }}
  thead th .sort-indicator {{ font-size: 0.7em; opacity: 0.7; margin-left: 2px; }}
  tbody td {{
    padding: 10px 14px;
    border-bottom: 1px solid var(--gridline);
    vertical-align: middle;
  }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:nth-child(even) {{ background: var(--page-plane); }}
  td.date {{ font-variant-numeric: tabular-nums; white-space: nowrap; color: var(--text-secondary); }}
  td.company, td.role {{
    max-width: 240px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}
  .hint {{ color: var(--text-muted); cursor: help; }}

  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 600;
    white-space: nowrap;
  }}
  .badge-applied   {{ background: var(--info-blue);      color: #fff; }}
  .badge-interview {{ background: var(--status-warning);  color: #1a1200; }}
  .badge-offer     {{ background: var(--status-good);     color: #fff; }}
  .badge-rejected  {{ background: var(--status-critical); color: #fff; }}

  @media (max-width: 480px) {{
    td.company, td.role {{ max-width: 130px; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Geoff's Job Application Tracker</h1>
    <p>Generated {html.escape(generated_at)} &middot; {total} email{"s" if total != 1 else ""} matched</p>
  </header>

  <div class="stats">
    <div class="card total">
      <div class="card-label">Total applications</div>
      <div class="card-value">{total}</div>
    </div>
{stat_cards}
  </div>
  {unclear_note}

  <div class="chart-card">
    <h2>Status breakdown</h2>
{chart_rows}
  </div>

  <input class="search-box" id="searchBox" type="text"
    placeholder="Filter by company or role&hellip;" oninput="filterRows()"
    aria-label="Filter by company or role">

  <div class="table-wrap">
    <table id="jobsTable">
      <thead>
        <tr>
          <th data-key="date" data-col="0">Date<span class="sort-indicator"></span></th>
          <th data-key="company" data-col="1">Company/Platform<span class="sort-indicator"></span></th>
          <th data-key="role" data-col="2">Role<span class="sort-indicator"></span></th>
          <th data-key="status" data-col="3">Status<span class="sort-indicator"></span></th>
        </tr>
      </thead>
      <tbody>
{chr(10).join(rows)}
      </tbody>
    </table>
  </div>
</div>
<script>
  function filterRows() {{
    var q = document.getElementById('searchBox').value.trim().toLowerCase();
    document.querySelectorAll('#jobsTable tbody tr').forEach(function (tr) {{
      var company = (tr.children[1].dataset.sort || '').toLowerCase();
      var role = (tr.children[2].dataset.sort || '').toLowerCase();
      tr.style.display = (!q || company.indexOf(q) !== -1 || role.indexOf(q) !== -1) ? '' : 'none';
    }});
  }}

  var sortState = {{ key: null, dir: 1 }};
  function sortTable(th) {{
    var key = th.dataset.key;
    var col = parseInt(th.dataset.col, 10);
    sortState.dir = (sortState.key === key) ? sortState.dir * -1 : 1;
    sortState.key = key;

    var tbody = document.querySelector('#jobsTable tbody');
    var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    rows.sort(function (a, b) {{
      var av = a.children[col].dataset.sort || '';
      var bv = b.children[col].dataset.sort || '';
      return av.localeCompare(bv, undefined, {{ numeric: true, sensitivity: 'base' }}) * sortState.dir;
    }});
    rows.forEach(function (r) {{ tbody.appendChild(r); }});

    document.querySelectorAll('#jobsTable thead th .sort-indicator').forEach(function (s) {{ s.textContent = ''; }});
    th.querySelector('.sort-indicator').textContent = sortState.dir === 1 ? ' \\u25B2' : ' \\u25BC';
  }}

  document.querySelectorAll('#jobsTable thead th').forEach(function (th) {{
    th.addEventListener('click', function () {{ sortTable(th); }});
  }});
</script>
</body>
</html>
'''


def write_and_open_report(entries, oldest_first, open_browser=True):
    html_text = render_html(entries, oldest_first)
    REPORT_FILE.write_text(html_text, encoding="utf-8")
    print(f"Wrote report to {REPORT_FILE}")
    if open_browser:
        webbrowser.open(REPORT_FILE.as_uri())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--query", default=DEFAULT_QUERY, help="Gmail search query override")
    parser.add_argument("--max-results", type=int, default=1000, help="max emails to scan (default 1000)")
    parser.add_argument("--oldest-first", action="store_true", help="sort chronologically instead of newest-first")
    parser.add_argument("--no-open", action="store_true", help="don't automatically open the report in a browser")
    args = parser.parse_args()

    service = get_gmail_service()
    print("Searching inbox...", file=sys.stderr)
    messages = fetch_messages(service, args.query, args.max_results)
    if not messages:
        print("No matching emails found.")
        return

    entries = build_entries(messages)
    entries = dedupe_interviews(entries)
    write_and_open_report(entries, args.oldest_first, open_browser=not args.no_open)


if __name__ == "__main__":
    main()
