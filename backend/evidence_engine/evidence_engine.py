"""SentinelAI Threat Evidence Engine v2.

Converts a URL + page metadata into a structured *risk evidence* vector:
every detector is {feature, category, value(bool|gated number), severity,
confidence, specificity, evidence_strength}. Detectors with `value` falsy or
below a gating threshold are treated as NOT triggered and contribute no risk.

This is the deterministic Stage-1 / Stage-2 feature extraction layer.
"""
import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Offline knowledge bases (no network dependency)
# ---------------------------------------------------------------------------

# Common high-traffic registrable (second-level) domains. Being listed here is
# one *negative* evidence source ("likely legitimate"), never a decision alone.
KNOWN_DOMAINS = {
    'google', 'gmail', 'youtube', 'facebook', 'instagram', 'whatsapp', 'x',
    'twitter', 'linkedin', 'microsoft', 'microsoftonline', 'office', 'outlook',
    'live', 'apple', 'icloud', 'amazon', 'paypal', 'netflix', 'spotify',
    'github', 'gitlab', 'bitbucket', 'stackoverflow', 'wikipedia', 'reddit',
    'yahoo', 'bing', 'duckduckgo', 'cloudflare', 'wordpress', 'wix', 'shopify',
    'stripe', 'adobe', 'dropbox', 'slack', 'zoom', 'cloud', 'aws', 'azure',
    'vercel', 'netlify', 'notion', 'figma', 'canva', 'medium', 'quora',
    'nytimes', 'bbc', 'cnn', 'washingtonpost', 'theguardian', 'forbes',
    'bloomberg', 'reuters', 'espn', 'cnet', 'usatoday', 'wsj', 'ft',
    'example', 'examplecom', 'test',
    'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'capitalone', 'usbank',
    'hsbc', 'barclays', 'santander', 'ing', 'revolut', 'wise', 'payoneer',
    'ebay', 'etsy', 'alibaba', 'flipkart', 'taobao', 'jd', 'rakuten',
    'baidu', 'qq', 'taobao', 'weibo', 'alipay', 'tencent', 'sina',
    # LatAm / Brazil majors (frequent phishing targets, own their promos)
    'americanas', 'magazineluiza', 'casasbahia', 'mercadolivre',
    'mercadolibre', 'mercado', 'picpay', 'nubank', 'itau', 'bradesco',
    'bancodobrasil', 'caixa', 'santander', 'submarino', 'shoptime',
    'pontofrio', 'webmotors', 'olx', 'decolar', 'airbnb', 'booking',
}

# Common / known TLDs. A host whose TLD is absent here is a strong identity
# anomaly (e.g. a disposable or on-the-fly domain used by phishers).
KNOWN_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
    'io', 'co', 'me', 'ai', 'app', 'dev', 'tech', 'store', 'shop', 'online',
    'site', 'live', 'top', 'club', 'page', 'mobi', 'info', 'biz',
    'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'in', 'br', 'ru', 'es',
    'it', 'nl', 'se', 'no', 'ch', 'at', 'be', 'dk', 'fi', 'ie', 'pt', 'pl',
    'cz', 'sk', 'hu', 'gr', 'tr', 'mx', 'ar', 'co', 'za', 'ng', 'ae', 'sa',
    'il', 'sg', 'hk', 'tw', 'kr', 'my', 'th', 'vn', 'ph', 'id', 'pk', 'bd',
    'is', 'ly', 'gd', 'to', 'so',  # common shortener / infra ccTLDs
    'github.io', 'blogspot.com', 'wordpress.com', 'wixsite.com', 'pages.dev',
    'netlify.app', 'vercel.app', 'onrender.com', 'my.id', 'co.id', 'com.br',
}

# Multi-label public suffixes (second-level TLDs). Hosts under these treat the
# *third* label as the registrable domain; e.g. saral.iitjammu.ac.in is
# registrable `iitjammu` under the academic suffix `ac.in`.
KNOWN_PUBLIC_SUFFIXES = {
    'ac.in', 'co.in', 'net.in', 'org.in', 'res.in', 'gov.in', 'edu.in',
    'mil.in', 'firm.in', 'gen.in', 'ind.in', 'nic.in',
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'net.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'edu.au', 'gov.au', 'org.au', 'net.au', 'id.au', 'asn.au',
    'co.nz', 'org.nz', 'ac.nz', 'govt.nz', 'net.nz', 'geek.nz',
    'co.jp', 'ac.jp', 'go.jp', 'or.jp', 'ne.jp', 'gr.jp',
    'com.br', 'com.mx', 'com.ar', 'com.co', 'com.pe',
    'gov.br', 'edu.br', 'mil.br',
    'co.il', 'org.il', 'ac.il', 'gov.il', 'muni.il',
    'co.za', 'org.za', 'ac.za', 'gov.za', 'net.za',
    'com.tr', 'org.tr', 'edu.tr', 'gov.tr', 'net.tr',
    'com.sg', 'edu.sg', 'gov.sg', 'org.sg',
    'com.my', 'edu.my', 'gov.my', 'org.my',
    'com.cn', 'edu.cn', 'gov.cn', 'org.cn', 'net.cn',
    'co.id', 'ac.id', 'or.id', 'web.id', 'go.id',
    'com.tw', 'edu.tw', 'gov.tw', 'org.tw', 'net.tw',
    'com.hk', 'edu.hk', 'gov.hk', 'org.hk', 'net.hk',
    'co.kr', 'ac.kr', 'go.kr', 'or.kr', 're.kr',
    'com.vn', 'edu.vn', 'gov.vn', 'org.vn', 'net.vn',
    'com.ph', 'edu.ph', 'gov.ph', 'org.ph',
    'com.ng', 'edu.ng', 'gov.ng', 'org.ng',
    'com.pk', 'edu.pk', 'gov.pk', 'org.pk', 'net.pk',
    'com.bd', 'edu.bd', 'gov.bd', 'org.bd',
    'com.eg', 'edu.eg', 'gov.eg',
    'co.th', 'ac.th', 'go.th', 'or.th', 'in.th',
    'com.kw', 'edu.kw', 'gov.kw',
    'co.om', 'gov.om', 'edu.om',
    'com.qa', 'edu.qa', 'gov.qa',
    'com.sa', 'edu.sa', 'gov.sa',
    'com.ae', 'gov.ae', 'ac.ae',
    'ir', 'ac.ir', 'co.ir', 'gov.ir',
    'edu.ru', 'gov.ru', 'ac.ru', 'com.ru', 'org.ru',
    'edu.ua', 'gov.ua', 'ac.ua',
    'gov.in', 'nic.in',
}

# Suffixes reserved by their registries for government / academic institutions
# ONLY (registrations are restricted). These legitimately host credential
# pages, so they suppress impersonation heuristics. Commercial suffixes like
# com.au / co.uk / com.br must NOT appear here even though they are multi-part
# public suffixes used for registrable-domain extraction above.
PUBLIC_SECTOR_SUFFIXES = {
    # India
    'gov.in', 'edu.in', 'mil.in', 'nic.in', 'ac.in', 'res.in',
    # Brazil
    'gov.br', 'edu.br', 'mil.br',
    # United Kingdom
    'gov.uk', 'ac.uk',
    # Australia
    'gov.au', 'edu.au',
    # New Zealand
    'govt.nz', 'ac.nz',
    # Japan
    'go.jp', 'ac.jp',
    # Israel
    'gov.il', 'ac.il', 'muni.il',
    # South Africa
    'gov.za', 'ac.za',
    # Turkey
    'edu.tr', 'gov.tr',
    # Singapore / Malaysia
    'edu.sg', 'gov.sg', 'edu.my', 'gov.my',
    # China
    'edu.cn', 'gov.cn',
    # Indonesia
    'ac.id', 'go.id',
    # Taiwan / Hong Kong
    'edu.tw', 'gov.tw', 'edu.hk', 'gov.hk',
    # Korea
    'ac.kr', 'go.kr', 're.kr',
    # Vietnam / Philippines
    'edu.vn', 'gov.vn', 'edu.ph', 'gov.ph',
    # Nigeria / Pakistan / Bangladesh
    'edu.ng', 'gov.ng', 'edu.pk', 'gov.pk', 'edu.bd', 'gov.bd',
    # Egypt
    'edu.eg', 'gov.eg',
    # Thailand
    'ac.th', 'go.th',
    # Gulf states
    'edu.kw', 'gov.kw', 'gov.om', 'edu.om', 'edu.qa', 'gov.qa',
    'edu.sa', 'gov.sa', 'gov.ae', 'ac.ae',
    # Iran / Russia / Ukraine
    'ac.ir', 'gov.ir', 'edu.ru', 'gov.ru', 'ac.ru',
    'edu.ua', 'gov.ua', 'ac.ua',
}

# Free / anonymous web-hosting providers that require no identity checks.
# Heavily abused for throwaway phishing pages; a page served from one of
# these suffixes is suspicious even when its content looks clean.
FREE_WEBHOST_SUFFIXES = {
    '0fees.net', 'orgfree.com', 'byethost.com', 'byet.net',
    '000webhostapp.com', '000webhost.com', 'x10.mx', 'x10hosting.com',
    'myregisteredsite.com', 'ifastnet.com', 'freevar.com', 'unaux.com',
    'rf.gd', 'pp.ua',
}

# Portuguese/Spanish loyalty-promo scam vocabulary (Banco do Brasil / bank
# points scams). Matched as substrings of the URL on unknown, non-protected
# hosts only — legitimate stores run promos on their own known domains.
PROMO_SCAM_KEYWORDS = (
    'promocao', 'promoo', 'fidelidade', 'pontosfidelidade', 'premio',
    'premiado', 'sorteio', 'brinde', 'resgate', 'cashback', 'milhas',
    'clubebradesco', 'portalbradesco',
)

# Popular URL shorteners. They hide the real destination, so they deny the
# identity layer any signal — worth recording as evidence by itself.
URL_SHORTENER_HOSTS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cutt.ly', 'rb.gy',
    'shorturl.at', 'shorten.is', 'tiny.cc', 'bit.do', 'rebrand.ly', 'ow.ly',
    'buff.ly', 's.id', 'v.gd', 'ouo.io', 'adf.ly', 'exe.io', 'shrinkme.io',
    'clk.sh', 'linkvertise.com',
}

# Endpoints that serve raw user-uploaded content for direct download. The
# page itself is benign-looking; the payload is what attacks the user, so we
# record the endpoint instead of issuing a clean "safe" verdict.
DIRECT_DOWNLOAD_ENDPOINTS = (
    'pastebin.com/raw/',
    'drive.usercontent.google.com/download',
    'docs.google.com/uc?',
    'ydray.com/get/',
    'transfer.sh/', 'filebin.net/', 'bashupload.com/',
)


def registrable_info(labels):
    """Return (registrable_label, subdomain_count, public_suffix, is_public_sector).

    `labels` is the pre-split host label list (no empty parts).
    """
    if not labels:
        return '', 0, '', False
    public_parts = 2 if (
        len(labels) >= 2 and '.'.join(labels[-2:]) in KNOWN_PUBLIC_SUFFIXES
    ) else 1
    suffix = '.'.join(labels[-public_parts:])
    reg_lbl = labels[-public_parts - 1] if len(labels) > public_parts else (labels[-1] if labels else '')
    sub_count = max(0, len(labels) - public_parts - 1)
    # Only restricted gov/edu suffixes count as public sector; commercial
    # multi-part TLDs (com.au, co.uk, com.br, ...) do NOT.
    public_sector = (suffix in PUBLIC_SECTOR_SUFFIXES) or (labels[-1] in {'edu', 'gov', 'mil'})
    return reg_lbl, sub_count, suffix, public_sector
# High-value brands used for brand impersonation detection.
BRAND_NAMES = [
    'google', 'gmail', 'youtube', 'microsoft', 'office', 'outlook',
    'apple', 'icloud', 'paypal', 'amazon', 'facebook', 'instagram',
    'whatsapp', 'twitter', 'linkedin', 'netflix', 'spotify', 'ebay', 'etsy',
    'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'capitalone',
    'usbank', 'hsbc', 'barclays', 'santander', 'revolut', 'wise', 'payoneer',
    'stripe', 'shopify', 'adobe', 'dropbox', 'slack', 'zoom', 'github',
    'venmo', 'coinbase', 'binance', 'crypto', 'metamask',
    # Additional brands commonly targeted in phishing
    'yahoo', 'remax', 'bb', 'bancodobrasil', 'itau', 'bradesco', 'caixa',
    'nubank', 'inter', 'original', 'c6bank', 'picpay', 'mercadopago',
    'mercadolivre', 'americanas', 'magazineluiza', 'casasbahia', 'extra',
    'pontofrio', 'fastshop', 'kabum', 'webmotors', 'olx', 'airbnb',
    'booking', 'decolar', 'maxmilhas', '123milhas', 'cvc', 'submarino',
    'shoptime', 'ricardoeletro', 'leroymerlin', 'telhanorte', 'leroy',
    'samsung', 'lg', 'motorola', 'xiaomi', 'huawei', 'asus', 'lenovo',
    'dell', 'hp', 'acer', 'asus', 'msi', 'razer', 'logitech',
    'steam', 'epic', 'origin', 'uplay', 'battlenet', 'riot',
    'discord', 'telegram', 'signal', 'viber', 'skype', 'teams',
    'slack', 'zoom', 'webex', 'gotomeeting', 'bluejeans',
    'office365', 'azure', 'aws', 'cloudflare', 'digitalocean',
    'heroku', 'vercel', 'netlify', 'github', 'gitlab', 'bitbucket',
    'jira', 'confluence', 'trello', 'asana', 'monday', 'notion',
    'salesforce', 'hubspot', 'pipedrive', 'zendesk', 'freshdesk',
    'servicenow', 'workday', 'adp', 'paychex', 'gusto', 'quickbooks',
    'xero', 'wave', 'freshbooks', 'zoho', 'odoo', 'sap',
    'oracle', 'workday', 'servicenow', 'atlassian', 'jetbrains',
    'intellij', 'pycharm', 'webstorm', 'vscode', 'visualstudio',
    'docker', 'kubernetes', 'jenkins', 'circleci', 'travisci',
    'github', 'gitlab', 'bitbucket', 'jfrog', 'artifactory',
]

BRAND_DOMAINS = {
    'google': {'google.com', 'google.co.in', 'google.co.uk', 'goo.gl'},
    'gmail': {'gmail.com'},
    'youtube': {'youtube.com', 'youtu.be'},
    'microsoft': {'microsoft.com', 'microsoftonline.com', 'windows.com', 'msn.com'},
    'office': {'office.com', 'office365.com'},
    'outlook': {'outlook.com', 'hotmail.com'},
    'live': {'live.com'},
    'apple': {'apple.com', 'icloud.com'},
    'icloud': {'icloud.com'},
    'paypal': {'paypal.com', 'paypal.me'},
    'amazon': {'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amzn.to'},
    'facebook': {'facebook.com', 'fb.com', 'fb.me'},
    'instagram': {'instagram.com'},
    'whatsapp': {'whatsapp.com', 'wa.me'},
    'twitter': {'twitter.com', 't.co'},
    'x': {'x.com'},
    'linkedin': {'linkedin.com', 'lnkd.in'},
    'netflix': {'netflix.com'},
    'spotify': {'spotify.com'},
    'ebay': {'ebay.com'},
    'etsy': {'etsy.com'},
    'bankofamerica': {'bankofamerica.com', 'bofa.com'},
    'chase': {'chase.com'},
    'wellsfargo': {'wellsfargo.com'},
    'citibank': {'citibank.com', 'citi.com'},
    'capitalone': {'capitalone.com'},
    'usbank': {'usbank.com'},
    'hsbc': {'hsbc.com'},
    'barclays': {'barclays.com'},
    'santander': {'santander.com'},
    'revolut': {'revolut.com'},
    'wise': {'wise.com'},
    'payoneer': {'payoneer.com'},
    'stripe': {'stripe.com'},
    'shopify': {'shopify.com'},
    'adobe': {'adobe.com'},
    'dropbox': {'dropbox.com'},
    'slack': {'slack.com'},
    'zoom': {'zoom.us'},
    'github': {'github.com', 'github.io'},
    'venmo': {'venmo.com'},
    'coinbase': {'coinbase.com'},
    'binance': {'binance.com'},
    'crypto': {'crypto.com'},
    'metamask': {'metamask.io'},
    # Additional brands commonly targeted in phishing
    'yahoo': {'yahoo.com', 'yahoo.co.jp', 'yahoo.co.uk', 'ymail.com', 'rocketmail.com'},
    'remax': {'remax.com', 'remax.com.au', 'remax.ca', 'remax.fr', 'remax.pt'},
    'bb': {'bb.com.br', 'banco.br', 'bancodobrasil.com.br'},
    'bancodobrasil': {'bb.com.br', 'banco.br', 'bancodobrasil.com.br'},
    'itau': {'itau.com.br', 'itau.com'},
    'bradesco': {'bradesco.com.br', 'bradesco.com'},
    'caixa': {'caixa.gov.br', 'caixa.com.br'},
    'nubank': {'nubank.com.br', 'nubank.com'},
    'inter': {'inter.co', 'bancointer.com.br'},
    'original': {'original.com.br'},
    'c6bank': {'c6bank.com.br'},
    'picpay': {'picpay.com', 'picpay.com.br'},
    'mercadopago': {'mercadopago.com', 'mercadopago.com.br', 'mercadopago.com.mx'},
    'mercadolivre': {'mercadolivre.com', 'mercadolivre.com.br', 'mercadolibre.com', 'mercadolibre.com.ar'},
    'americanas': {'americanas.com.br', 'americanas.com'},
    'magazineluiza': {'magazineluiza.com.br', 'magazineluiza.com'},
    'casasbahia': {'casasbahia.com.br', 'casasbahia.com'},
    'extra': {'extra.com.br', 'extra.com'},
    'pontofrio': {'pontofrio.com.br'},
    'fastshop': {'fastshop.com.br'},
    'kabum': {'kabum.com.br'},
    'webmotors': {'webmotors.com.br'},
    'olx': {'olx.com.br', 'olx.pt', 'olx.com', 'olx.pl'},
    'airbnb': {'airbnb.com', 'airbnb.com.br'},
    'booking': {'booking.com', 'booking.com.br'},
    'decolar': {'decolar.com', 'decolar.com.br'},
    'maxmilhas': {'maxmilhas.com.br'},
    '123milhas': {'123milhas.com.br'},
    'cvc': {'cvc.com.br'},
    'submarino': {'submarino.com.br'},
    'shoptime': {'shoptime.com.br'},
    'ricardoeletro': {'ricardoeletro.com.br'},
    'leroymerlin': {'leroymerlin.com.br', 'leroymerlin.com'},
    'telhanorte': {'telhanorte.com.br'},
    'leroy': {'leroymerlin.com.br'},
    'samsung': {'samsung.com', 'samsung.com.br'},
    'lg': {'lg.com', 'lg.com.br'},
    'motorola': {'motorola.com', 'motorola.com.br'},
    'xiaomi': {'xiaomi.com', 'mi.com', 'mi.com.br'},
    'huawei': {'huawei.com', 'consumer.huawei.com'},
    'asus': {'asus.com', 'asus.com.br'},
    'lenovo': {'lenovo.com', 'lenovo.com.br'},
    'dell': {'dell.com', 'dell.com.br'},
    'hp': {'hp.com', 'hp.com.br'},
    'acer': {'acer.com', 'acer.com.br'},
    'msi': {'msi.com', 'msi.com.br'},
    'razer': {'razer.com', 'razer.com.br'},
    'logitech': {'logitech.com', 'logitech.com.br'},
    'steam': {'steampowered.com', 'store.steampowered.com'},
    'epic': {'epicgames.com'},
    'origin': {'origin.com'},
    'uplay': {'ubisoft.com', 'uplay.ubisoft.com'},
    'battlenet': {'battle.net'},
    'riot': {'riotgames.com', 'leagueoflegends.com'},
    'discord': {'discord.com', 'discord.gg'},
    'telegram': {'telegram.org', 't.me'},
    'signal': {'signal.org'},
    'viber': {'viber.com'},
    'skype': {'skype.com'},
    'teams': {'teams.microsoft.com'},
    'slack': {'slack.com'},
    'zoom': {'zoom.us', 'zoom.com'},
    'webex': {'webex.com'},
    'gotomeeting': {'gotomeeting.com'},
    'bluejeans': {'bluejeans.com'},
    'office365': {'office.com', 'office365.com'},
    'azure': {'azure.com', 'portal.azure.com'},
    'aws': {'aws.amazon.com', 'console.aws.amazon.com'},
    'cloudflare': {'cloudflare.com', 'dash.cloudflare.com'},
    'digitalocean': {'digitalocean.com', 'cloud.digitalocean.com'},
    'heroku': {'heroku.com', 'dashboard.heroku.com'},
    'vercel': {'vercel.com'},
    'netlify': {'netlify.app', 'app.netlify.com'},
    'github': {'github.com', 'github.io', 'github.dev'},
    'gitlab': {'gitlab.com'},
    'bitbucket': {'bitbucket.org'},
    'jira': {'atlassian.net', 'jira.com'},
    'confluence': {'atlassian.net', 'confluence.atlassian.com'},
    'trello': {'trello.com'},
    'asana': {'asana.com'},
    'monday': {'monday.com'},
    'notion': {'notion.so', 'notion.site'},
    'salesforce': {'salesforce.com', 'lightning.force.com'},
    'hubspot': {'hubspot.com', 'app.hubspot.com'},
    'pipedrive': {'pipedrive.com'},
    'zendesk': {'zendesk.com', 'zendesk.us'},
    'freshdesk': {'freshdesk.com'},
    'servicenow': {'servicenow.com'},
    'workday': {'workday.com', 'myworkday.com'},
    'adp': {'adp.com', 'my.adp.com'},
    'paychex': {'paychex.com'},
    'gusto': {'gusto.com'},
    'quickbooks': {'quickbooks.intuit.com', 'quickbooks.com'},
    'xero': {'xero.com', 'login.xero.com'},
    'wave': {'waveapps.com'},
    'freshbooks': {'freshbooks.com'},
    'zoho': {'zoho.com', 'zoho.eu', 'zoho.com.cn'},
    'odoo': {'odoo.com', 'odoo.sh'},
    'sap': {'sap.com', 'launchpad.sap.com'},
    'oracle': {'oracle.com', 'cloud.oracle.com'},
    'workday': {'workday.com', 'myworkday.com'},
    'servicenow': {'servicenow.com'},
    'atlassian': {'atlassian.net', 'atlassian.com'},
    'jetbrains': {'jetbrains.com', 'account.jetbrains.com'},
    'intellij': {'jetbrains.com'},
    'pycharm': {'jetbrains.com'},
    'webstorm': {'jetbrains.com'},
    'vscode': {'code.visualstudio.com', 'vscode.dev'},
    'visualstudio': {'visualstudio.microsoft.com', 'dev.azure.com'},
    'docker': {'docker.com', 'hub.docker.com'},
    'kubernetes': {'kubernetes.io', 'k8s.io'},
    'jenkins': {'jenkins.io'},
    'circleci': {'circleci.com'},
    'travisci': {'travis-ci.org', 'travis-ci.com'},
    'github': {'github.com', 'github.io', 'github.dev'},
    'gitlab': {'gitlab.com'},
    'bitbucket': {'bitbucket.org'},
    'jfrog': {'jfrog.io'},
    'artifactory': {'jfrog.io'},
}

# Brand ownership aliases: a brand's pages legitimately live under these
# brands' canonical domains (e.g. gmail.com, youtube.com <-> google.com).
BRAND_ALIASES = {
    'gmail': ['google'],
    'youtube': ['google'],
    'outlook': ['microsoft'],
    'live': ['microsoft'],
    'office': ['microsoft'],
    'icloud': ['apple'],
}


def _canonical_hosts(brand: str) -> set:
    hosts = set(BRAND_DOMAINS.get(brand, set()))
    for alias in BRAND_ALIASES.get(brand, []):
        hosts |= set(BRAND_DOMAINS.get(alias, set()))
    return hosts


# High-value credential keywords found in phishing-style paths.
HIGH_VALUE_KEYWORDS = (
    'verify', 'secure', 'account', 'security', 'login', 'signin', 'update',
    'billing', 'payment', 'password', 'recover', 'reset', 'confirm',
    'validate', 'unusual', 'suspend', 'reactivat', 'invoice', 'activ',
    'support', 'customer', 'wallet', 'bank', 'otp', '2fa', 'two-factor',
    # Portuguese / Spanish credential vocabulary
    'cadastro', 'senha', 'acesso', 'portalseguro', 'internetbanking',
    'validacao', 'confirmacao', 'desbloqueio',
)

_SUSPICIOUS_PATH = re.compile(
    r'(?:[a-z0-9]+[-_])?(?:verify|secure|account|security|logi?n|signin|'
    r'session|update|billing|payment|password|recover|reset|confirm|validate|'
    r'unusual|suspend|reactivat|invoice|activ)[-_][a-z0-9]+',
    re.IGNORECASE,
)

IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
IPV6_RE = re.compile(r'^[0-9a-f:]+$', re.IGNORECASE)


def _is_ip(host: str) -> bool:
    host = host.strip('[]')
    if IPV4_RE.match(host):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _edit_distance(a: str, b: str) -> int:
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _extract_claimed_brands(title: str, hints: str) -> List[str]:
    hay = ' '.join(x for x in (title or '', hints or '') if x).lower()
    found = []
    for brand in BRAND_NAMES:
        pattern = re.compile(r'(?<![a-z0-9])' + re.escape(brand) + r'(?![a-z0-9])')
        if pattern.search(hay):
            found.append(brand)
    return found


class ThreatEvidenceEngine:
    """Two-tier evidence extraction.

    Tier 0 (always, ~free): URL/domain/TLS metadata parsing.
    Tier 1 (available): form / credential-flow / behavioral metadata supplied by
    the content script. Deep analysis is only triggered for ambiguous cases.
    """

    def build_evidence(self, url: str, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        metadata = metadata or {}
        parsed = urlparse(url)
        host = (parsed.netloc or '').split('@')[-1].lower()
        host = host.split(':')[0] if ':' in host and not host.startswith('[') else host
        domain = host
        path = parsed.path or '/'

        labels = [l for l in domain.split('.') if l]
        tld = labels[-1] if labels else ''
        registrable, subdomain_count, public_suffix, public_sector = registrable_info(labels)
        is_ip = _is_ip(host)
        punycode = host.startswith('xn--') or any(l.startswith('xn--') for l in labels)
        has_at_sign = '@' in parsed.netloc
        known_domain = registrable in KNOWN_DOMAINS

        # ---- metadata (camelCase and snake_case both accepted) -------------
        def mget(*keys, default=None):
            for k in keys:
                if k in metadata:
                    return metadata[k]
            return default

        password_fields = int(mget('passwordFields', 'password_fields', default=0) or 0)
        form_count = int(mget('forms', 'form_count', default=0) or 0)
        hidden_elements = int(mget('hiddenElements', 'hidden_elements', default=0) or 0)
        external_scripts = int(mget('externalScripts', 'external_scripts', default=0) or 0)
        iframes = int(mget('iframes', default=0) or 0)
        permission_requests = int(mget('permissionRequests', 'permission_requests', default=0) or 0)
        prompt_signals = int(mget('promptInjectionSignals', 'prompt_injection_signals', default=0) or 0)
        downloads = int(mget('downloadTriggers', 'download_triggers', default=0) or 0)
        clipboard = int(mget('clipboardAccess', 'clipboard_access', default=0) or 0)
        otp_request = bool(mget('otpRequest', 'otp_request', default=False))
        hidden_login_form = bool(mget('hiddenLoginForm', 'hidden_login_form', default=False))
        obfuscated = bool(mget('obfuscatedContent', 'obfuscated_content', default=False))
        login_intent = bool(mget('hasLoginIntent', default=False)) or 'login' in path or 'signin' in path
        title = mget('title', default='')
        brand_hints = mget('brandHints', 'brand_hints', default='')
        form_action_mismatch = mget('formActionDomainMismatch', 'form_action_domain_mismatch')
        cred_mismatch = mget('credentialSubmissionDestinationMismatch', 'credential_submission_destination_mismatch')
        form_destination = mget('formDestination', 'form_destination', default='')  # where the login form posts
        submitted_destination = mget('submittedDestination', 'submitted_destination', default='')
        https = (parsed.scheme or '').lower() == 'https'
        redirects = int(mget('redirectCount', 'redirect_count', default=0) or 0)

        # ---- identity / host heuristics ------------------------------------
        tld_known = tld in KNOWN_TLDS
        hyphen_heavy = registrable.count('-') >= 2
        excessive_subdomains = subdomain_count >= 3
        numeric_reg = bool(re.search(r'\d', registrable)) and len(registrable) >= 5
        path_lower = (path or '').lower()
        suspicious_path = bool(_SUSPICIOUS_PATH.search(path)) or any(
            k in path_lower for k in HIGH_VALUE_KEYWORDS)
        # Credential vocabulary on a path, but only meaningful when the host
        # is NOT a known brand (github.com/login must never fire this).
        credential_path = (
            not known_domain and not public_sector
            and any(k in path_lower for k in HIGH_VALUE_KEYWORDS))

        # ---- brand impersonation -------------------------------------------
        claimed_brands = _extract_claimed_brands(str(title), str(brand_hints))
        brand_impersonation = None
        brand_claimed = None
        for brand in claimed_brands:
            canonical = _canonical_hosts(brand)
            domain_match = any(
                host == d or host.endswith('.' + d) or host.endswith('.' + d + '.')
                for d in canonical
            )
            if not domain_match and canonical:
                brand_impersonation = brand
                brand_claimed = brand
                break
            if not domain_match:
                brand_impersonation = brand_impersonation or brand
                brand_claimed = brand_claimed or brand
        # even without title hints, a brand in the registrable domain with a
        # non-canonical host is a lookalike
        lookalike_brand = None
        for brand in BRAND_NAMES:
            canonical = _canonical_hosts(brand)
            if any(host == d or host.endswith('.' + d) for d in canonical):
                continue
            if (registrable.startswith(brand + '-') or brand + '-' in registrable
                    or registrable.startswith(brand)):
                lookalike_brand = brand
                break

        suspicious_host = (
            not tld_known
            or is_ip
            or has_at_sign
            or punycode
            or hyphen_heavy
            or excessive_subdomains
            or lookalike_brand is not None
        )

        # ---- credential-flow consistency -----------------------------------
        def _destination_mismatch(dest: str) -> bool:
            if not dest:
                return False
            try:
                dest_host = urlparse(dest if '://' in dest else '//' + dest).netloc.split('@')[-1].split(':')[0].lower()
            except Exception:
                dest_host = ''
            return bool(dest_host and dest_host not in (host, '') and not host.endswith('.' + dest_host) and not dest_host.endswith(host))

        if cred_mismatch is None:
            cred_mismatch = bool(submitted_destination and _destination_mismatch(submitted_destination))
        if form_action_mismatch is None:
            form_action_mismatch = bool(form_destination and _destination_mismatch(form_destination))

        # A login form on an unfamiliar, suspicious host is a phishing signature --
        # unless the page is on trusted public-sector infrastructure (education /
        # government), where subdomained logins are normal.
        credentials_on_unknown_target = (
            password_fields > 0
            and not known_domain
            and not public_sector
            and (suspicious_host or redirects >= 1)
        )

        # ---- build structured detectors -------------------------------------
        # Weak behavioral signals (hidden elements, external scripts, obfuscated
        # content) are common on legitimate sites, so they only count against
        # the page when the host is NOT already covered by protective context
        # (known domain / public-sector infrastructure).
        hidden_behavior_ctx = not known_domain and not public_sector
        detectors: List[Dict[str, Any]] = []

        def add(feature, category, value, severity='low', confidence=0.5,
                specificity='low', strength=None, note='', polarity='positive'):
            if strength is None:
                strength = confidence
            detectors.append({
                'feature': feature,
                'category': category,
                'value': value,
                'severity': severity,
                'confidence': round(confidence, 3),
                'specificity': specificity,
                'evidence_strength': round(float(strength), 3),
                'note': note,
                'polarity': polarity,
            })

        # ---- identity -------------------------------------------------------
        add('domain_is_ip', 'identity', is_ip, 'critical' if is_ip else 'low',
            0.95 if is_ip else 0.1, 'very_high', 0.95 if is_ip else 0.1)
        add('url_has_at_sign', 'identity', has_at_sign, 'critical' if has_at_sign else 'low',
            0.95 if has_at_sign else 0.1, 'very_high', 0.95 if has_at_sign else 0.1)
        add('punycode_homoglyph', 'identity', punycode, 'high' if punycode else 'low',
            0.9 if punycode else 0.1, 'high', 0.9 if punycode else 0.1)
        add('lookalike_domain', 'identity', bool(hyphen_heavy or excessive_subdomains),
            'high' if (hyphen_heavy or excessive_subdomains) else 'low',
            0.75 if (hyphen_heavy or excessive_subdomains) else 0.1,
            'high', 0.7 if (hyphen_heavy or excessive_subdomains) else 0.1)
        add('unknown_tld', 'identity', not tld_known,
            'high' if not tld_known else 'low',
            0.7 if not tld_known else 0.1, 'medium', 0.6 if not tld_known else 0.1)
        add('suspicious_path', 'identity', suspicious_path,
            'medium' if suspicious_path else 'low',
            0.6 if suspicious_path else 0.1, 'medium', 0.55 if suspicious_path else 0.1)
        add('credential_path_keywords', 'identity', credential_path,
            'medium' if credential_path else 'low',
            0.6 if credential_path else 0.1, 'medium',
            0.55 if credential_path else 0.1)
        add('lookalike_brand_domain', 'identity', lookalike_brand is not None,
            'high' if lookalike_brand else 'low',
            0.85 if lookalike_brand else 0.1, 'high', 0.85 if lookalike_brand else 0.1)
        add('brand_impersonation', 'identity', brand_impersonation is not None,
            'high' if brand_impersonation else 'low',
            0.9 if brand_impersonation else 0.1, 'very_high', 0.9 if brand_impersonation else 0.1)
        add('known_domain', 'identity', known_domain,
            'low', 0.9 if known_domain else 0.1, 'medium',
            0.8 if known_domain else 0.1, polarity='negative')
        add('public_sector_domain', 'identity', public_sector,
            'low', 0.9 if public_sector else 0.1, 'medium',
            0.8 if public_sector else 0.1, polarity='negative')
        add('domain_login_keyword', 'identity', any(k in ''.join(labels) for k in ('login', 'account', 'signin')),
            'medium' if any(k in ''.join(labels) for k in ('login', 'account', 'signin')) else 'low',
            0.5 if any(k in ''.join(labels) for k in ('login', 'account', 'signin')) else 0.1,
            'medium', 0.4 if any(k in ''.join(labels) for k in ('login', 'account', 'signin')) else 0.1)
        add('has_https', 'identity', https, 'low',
            0.4 if not https else 0.9, 'low', (0.3 if not https else 0.7),
            polarity='negative')

        # ---- URL-based brand / phishing-kit heuristics -----------------------
        # Brand name appearing in path when host is not the brand's domain
        brand_in_path = False
        if not known_domain and not public_sector:
            lower_path = path.lower()
            # Segments with file extensions stripped: 'perfilbb.php' -> 'perfilbb'
            segments = [
                re.sub(r'\.(html?|php[0-9]?|aspx?|jsp|cgi|cfm)$', '', s)
                for s in re.split(r'/+', lower_path) if s
            ]
            for brand in BRAND_NAMES:
                canonical = _canonical_hosts(brand)
                if any(host == d or host.endswith('.' + d) for d in canonical):
                    continue
                pattern = re.compile(
                    r'(?<![a-z0-9])' + re.escape(brand) + r'(?![a-z0-9])',
                    re.IGNORECASE)
                if pattern.search(lower_path):
                    brand_in_path = True
                    break
                # Very short brand tokens (bb, hp, lg) get glued onto local
                # words by kit builders: perfilbb, acessobb, portalbb, ...
                if len(brand) <= 3 and any(
                        seg.endswith(brand) and len(seg) > len(brand)
                        for seg in segments):
                    brand_in_path = True
                    break

        # Phishing kit URL markers (PayPal, generic credential harvesters)
        phish_kit_url = False
        if not known_domain and not public_sector:
            url_lower = url.lower()
            if ('webscr' in url_lower or
                'cmd=_login-run' in url_lower or
                'cmd=_login-submit' in url_lower or
                'dispatch=5885d80a13c0db1f' in url_lower or
                '/confirmaccount' in url_lower or
                'account-login' in url_lower or
                'secure-login' in url_lower or
                'verify-account' in url_lower or
                'session-expired' in url_lower or
                'update-card' in url_lower or
                'signin-verify' in url_lower or
                '/PortalSeguro/' in url_lower):
                phish_kit_url = True

        # Free / anonymous hosting suffix under the page's registrable domain
        free_hosting = any(
            host == s or host.endswith('.' + s) for s in FREE_WEBHOST_SUFFIXES)

        # Loyalty-promo scam vocabulary on a non-protected host (Brazilian
        # bank points scams: promocaopontosfidelidade.k6.com.br etc.)
        promo_scam = (
            not known_domain and not public_sector
            and any(k in url.lower() for k in PROMO_SCAM_KEYWORDS))

        # URL shortener as the visible host — destination identity is hidden.
        url_shortener = (
            host in URL_SHORTENER_HOSTS
            or any(host.endswith('.' + s) for s in URL_SHORTENER_HOSTS))

        # Raw user-content download endpoints (payload delivery channels).
        direct_download = any(mk in url.lower() for mk in DIRECT_DOWNLOAD_ENDPOINTS)

        # ---- add new identity detectors ------------------------------------
        add('brand_in_path', 'identity', brand_in_path,
            'high' if brand_in_path else 'low',
            0.85 if brand_in_path else 0.1, 'very_high',
            0.85 if brand_in_path else 0.1)
        add('phish_kit_url', 'identity', phish_kit_url,
            'critical' if phish_kit_url else 'low',
            0.95 if phish_kit_url else 0.1, 'very_high',
            0.95 if phish_kit_url else 0.1)
        add('free_hosting_subdomain', 'identity', free_hosting,
            'medium' if free_hosting else 'low',
            0.7 if free_hosting else 0.1, 'medium',
            0.65 if free_hosting else 0.1)
        add('promo_scam_keywords', 'content', promo_scam,
            'medium' if promo_scam else 'low',
            0.75 if promo_scam else 0.1, 'high',
            0.7 if promo_scam else 0.1)
        add('url_shortener_host', 'identity', url_shortener,
            'medium' if url_shortener else 'low',
            0.6 if url_shortener else 0.1, 'high',
            0.55 if url_shortener else 0.1)
        add('direct_download_endpoint', 'content', direct_download,
            'low' if direct_download else 'low',
            0.5 if direct_download else 0.1, 'medium',
            0.4 if direct_download else 0.1)

        # ---- interaction (credentials) --------------------------------------
        add('password_field_present', 'interaction', password_fields > 0,
            'medium' if password_fields > 0 else 'low',
            0.6 if password_fields > 0 else 0.1, 'low',
            0.5 if password_fields > 0 else 0.1)
        add('otp_request', 'interaction', otp_request,
            'medium' if otp_request else 'low',
            0.6 if otp_request else 0.1, 'medium',
            0.55 if otp_request else 0.1)
        add('login_intent', 'interaction', login_intent,
            'low', 0.5 if login_intent else 0.1, 'low',
            0.4 if login_intent else 0.1)
        add('credentials_on_unknown_target', 'interaction', credentials_on_unknown_target,
            'high' if credentials_on_unknown_target else 'low',
            0.9 if credentials_on_unknown_target else 0.1, 'high',
            0.85 if credentials_on_unknown_target else 0.1)

        # ---- credential flow (strongest) -------------------------------------
        add('form_action_domain_mismatch', 'identity', bool(form_action_mismatch),
            'medium' if form_action_mismatch else 'low',
            0.6 if form_action_mismatch else 0.1, 'medium',
            0.45 if form_action_mismatch else 0.1)
        add('credential_submission_mismatch', 'identity', bool(cred_mismatch),
            'critical' if cred_mismatch else 'low',
            0.95 if cred_mismatch else 0.1, 'very_high',
            0.95 if cred_mismatch else 0.1)

        # ---- behavior --------------------------------------------------------
        add('hidden_elements_count', 'behavior', hidden_elements >= 8 and hidden_behavior_ctx,
            'high' if (hidden_elements >= 8 and hidden_behavior_ctx) else 'low',
            0.6 if (hidden_elements >= 8 and hidden_behavior_ctx) else 0.1, 'medium',
            min(0.7, 0.4 + hidden_elements * 0.02) if (hidden_elements >= 8 and hidden_behavior_ctx) else 0.1)
        add('external_script_count', 'behavior', external_scripts >= 14 and hidden_behavior_ctx,
            'medium' if (external_scripts >= 14 and hidden_behavior_ctx) else 'low',
            0.5 if (external_scripts >= 14 and hidden_behavior_ctx) else 0.1, 'low',
            min(0.6, 0.35 + external_scripts * 0.015) if (external_scripts >= 14 and hidden_behavior_ctx) else 0.1)
        add('hidden_login_form', 'behavior', hidden_login_form,
            'high' if hidden_login_form else 'low',
            0.9 if hidden_login_form else 0.1, 'high',
            0.9 if hidden_login_form else 0.1)
        add('obfuscated_content', 'behavior', obfuscated and hidden_behavior_ctx,
            'medium' if (obfuscated and hidden_behavior_ctx) else 'low',
            0.6 if (obfuscated and hidden_behavior_ctx) else 0.1, 'medium',
            0.5 if (obfuscated and hidden_behavior_ctx) else 0.1)
        add('excessive_iframes', 'behavior', iframes >= 4,
            'medium' if iframes >= 4 else 'low',
            0.5 if iframes >= 4 else 0.1, 'low',
            0.4 if iframes >= 4 else 0.1)
        add('redirect_chain', 'behavior', redirects >= 2,
            'medium' if redirects >= 2 else 'low',
            0.55 if redirects >= 2 else 0.1, 'medium',
            0.5 if redirects >= 2 else 0.1)

        # ---- privacy ----------------------------------------------------------
        add('permission_requests', 'privacy', permission_requests > 0,
            'low' if permission_requests > 0 else 'low',
            0.5 if permission_requests > 0 else 0.1, 'low',
            0.4 if permission_requests > 0 else 0.1)
        add('clipboard_interaction', 'privacy', clipboard > 0,
            'medium' if clipboard > 0 else 'low',
            0.55 if clipboard > 0 else 0.1, 'medium',
            0.5 if clipboard > 0 else 0.1)
        add('download_trigger', 'privacy', downloads > 0,
            'medium' if downloads > 0 else 'low',
            0.55 if downloads > 0 else 0.1, 'medium',
            0.5 if downloads > 0 else 0.1)

        # ---- ai / social engineering ------------------------------------------
        # prompt-injection signals are only meaningful when corroborated
        prompt_triggered = prompt_signals >= 2 or (prompt_signals > 0 and hidden_login_form)
        add('prompt_injection_signals', 'ai', prompt_triggered,
            'high' if prompt_triggered else 'low',
            0.7 if prompt_triggered else 0.1, 'medium',
            0.6 if prompt_triggered else 0.1)

        # ----------------------------------------------------------------------
        triggered = [
            d for d in detectors
            if d.get('polarity', 'positive') == 'positive'
            and d.get('value')
            and d['value'] is not False
            and d['value'] != 0
        ]
        severity = 'low'
        threat_category = 'safe'
        if any(d['feature'] in ('credential_submission_mismatch',) and d['value'] for d in triggered):
            threat_category = 'phishing'
            severity = 'critical'
        elif any(d['feature'] in ('brand_impersonation', 'hidden_login_form', 'brand_in_path', 'phish_kit_url')
                 and bool(d['value']) for d in triggered):
            threat_category = 'phishing'
            severity = 'high'
        elif (any(d['feature'] == 'form_action_domain_mismatch' and bool(d['value']) for d in triggered)
              and any(d['feature'] in ('obfuscated_content', 'hidden_elements_count', 'unknown_tld')
                        and bool(d['value']) for d in triggered)):
            threat_category = 'phishing'
            severity = 'high'
        elif (any(d['feature'] == 'promo_scam_keywords' and bool(d['value']) for d in triggered)
              and any(d['feature'] in ('free_hosting_subdomain', 'obfuscated_content',
                                       'hidden_elements_count', 'excessive_subdomains',
                                       'numeric_reg', 'unknown_tld')
                        and bool(d['value']) for d in triggered)):
            threat_category = 'phishing'
            severity = 'high'
        elif any(d['category'] == 'privacy' and bool(d['value']) for d in triggered):
            threat_category = 'privacy'
            severity = 'medium'
        elif triggered:
            threat_category = 'suspicious'
            severity = 'medium'
        else:
            threat_category = 'safe'
            severity = 'low'

        confidence = min(0.99, sum(
            (float(d['evidence_strength']) for d in triggered), 0.0
        ) / 2.0) if triggered else 0.05

        supporting_evidence = [d['feature'] for d in triggered][:10]
        if not supporting_evidence:
            supporting_evidence = ['no_suspicious_signals_detected']

        legacy = {
            'identity_score': round(1.0 - min(0.7, 0.35 if not known_domain else 0.0), 2),
            'behavior_score': round(max(0.2, 1.0 - 0.3), 2),
            'interaction_score': round(0.55 if password_fields else 0.92, 2),
            'privacy_score': round(0.9 if not permission_requests else 0.7, 2),
            'ai_score': round(0.85 if not prompt_triggered else 0.6, 2),
        }

        return {
            'url': url,
            'domain': domain,
            'detectors': detectors,
            'threat_category': threat_category,
            'severity': severity,
            'confidence': round(confidence, 2),
            'supporting_evidence': supporting_evidence,
            'brand': brand_claimed or (lookalike_brand if lookalike_brand else None),
            'lookalike': lookalike_brand,
            'known_domain': known_domain,
            'suspicious_host': bool(suspicious_host),
            'https': https,
            **legacy,
        }