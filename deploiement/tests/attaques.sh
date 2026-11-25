#!/usr/bin/env bash
# Script de démonstration WAF ML - Validation du blocage (403) et du passage (200)
# Usage : bash deploiement/tests/attaques.sh [URL_BASE]

BASE_URL="${1:-http://localhost}"

echo "============================================================"
echo " Test du WAF sur $BASE_URL"
echo "============================================================"

test_req() {
    local label="$1"
    local method="$2"
    local path="$3"
    local data="$4"

    if [ "$method" = "POST" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "$data" "${BASE_URL}${path}")
    else
        code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "${BASE_URL}${path}")
    fi
    printf "[HTTP %s]  %s\n" "$code" "$label"
}

echo "--- 1. Trafic légitime (200 / 301 / 302 attendu) ---"
test_req "Accueil WordPress"                "GET"  "/" ""
test_req "Recherche légitime avec accent"   "GET"  "/?s=recette+de+crepes" ""
test_req "Recherche légitime apostrophe"    "GET"  "/?s=l%27%C3%A9t%C3%A9+%C3%A0+paris" ""
test_req "Commentaire légitime"             "POST" "/wp-comments-post.php" "comment=Super+article+merci&author=Nolhan"

echo ""
echo "--- 2. Injections SQL (403 attendu) ---"
test_req "SQLi UNION SELECT"                "GET"  "/?id=1%27%20union%20select%201,2,3--" ""
test_req "SQLi Boolean OR 1=1"              "GET"  "/?id=1%27%20or%20%271%27=%271" ""
test_req "SQLi Time-based SLEEP"            "GET"  "/?id=1%20and%20sleep(5)" ""
test_req "SQLi POST wp-login"               "POST" "/wp-login.php" "log=admin%27--&pwd=x"

echo ""
echo "--- 3. Cross-Site Scripting / XSS (403 attendu) ---"
test_req "XSS balise script"                "GET"  "/?s=%3Cscript%3Ealert(1)%3C/script%3E" ""
test_req "XSS onerror img"                  "GET"  "/?s=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E" ""

echo ""
echo "--- 4. Path Traversal & Command Injection (403 attendu) ---"
test_req "Path Traversal /etc/passwd"       "GET"  "/?file=../../../../etc/passwd" ""
test_req "Path Traversal URL-encoded"       "GET"  "/?page=..%2f..%2f..%2fetc%2fpasswd" ""
test_req "Command Injection ;cat"           "GET"  "/?ip=127.0.0.1;cat%20/etc/passwd" ""
test_req "Command Injection |whoami"        "GET"  "/?host=x%7Cwhoami" ""
test_req "Scan fichier .env"                "GET"  "/.env" ""

echo ""
echo "--- 5. Attaques obfusquées (403 attendu) ---"
test_req "SQLi obfusquée commentaires /**/" "GET"  "/?id=1%27/**/UnIoN/**/SeLeCt/**/1,2--" ""
test_req "SQLi double encodage URL"         "GET"  "/?id=1%2527%2520union%2520select%25201--" ""
test_req "XSS casse mixte <ScRiPt>"         "GET"  "/?q=%3CScRiPt%3Ealert(1)%3C/sCrIpT%3E" ""
test_req "XSS balise <svg/onload>"          "GET"  "/?q=%3Csvg/onload=alert(1)%3E" ""
echo "============================================================"