#!/usr/bin/env bash
# Test du WAF en conditions réelles sur les 3 sites du docker-compose (DVWA, WordPress, Juice Shop).
# Chaque requête légitime est rejouée deux fois : en curl nu, puis avec les en-têtes d'un navigateur.
#
# Usage : bash deploiement/tests/trafic_reel.sh
#   (pile démarrée : cd deploiement && docker compose up -d --build)
# Attendu : légitimes = tout sauf 403 ; attaques = 403. Code de sortie 1 s'il y a au moins une erreur.
# Les 401/404/409 des sites eux-mêmes (non authentifié, doublon...) prouvent que le WAF a laissé passer.

DVWA="${DVWA:-http://localhost:8080}"
WP="${WP:-http://localhost:8082}"
JUICE="${JUICE:-http://localhost:8083}"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
NAV=(-A "$UA" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
     -H "Accept-Language: fr-FR,fr;q=0.9" -H "Accept-Encoding: gzip, deflate, br")
ERREURS=0

verifie() {  # verifie <legit|attaque> <libelle> <curl args...>
  local type="$1" libelle="$2"; shift 2
  local code; code=$(curl -s -o /dev/null -w "%{http_code}" "$@")
  local ok=1
  if [ "$type" = attaque ]; then [ "$code" = 403 ] || ok=0; else [ "$code" != 403 ] && [ "$code" != 000 ] || ok=0; fi
  [ $ok = 1 ] && printf "  OK   %s  %s\n" "$code" "$libelle" || { printf "  ERR  %s  %s\n" "$code" "$libelle"; ERREURS=$((ERREURS + 1)); }
}

for mode in curl navigateur; do
  A=(); REF_LOGIN=(); REF_ARTICLE=()
  if [ "$mode" = navigateur ]; then   # un navigateur envoie toujours un Referer ; curl nu n'en envoie pas
    A=("${NAV[@]}"); REF_LOGIN=(-H "Referer: $WP/wp-login.php"); REF_ARTICLE=(-H "Referer: $WP/hello-world/")
  fi
  echo "=== Trafic légitime ($mode) ==="
  verifie legit "DVWA  page de login" "${A[@]}" "$DVWA/login.php"
  verifie legit "DVWA  page SQLi" "${A[@]}" "$DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
  verifie legit "WP    recherche" "${A[@]}" "$WP/?s=bonjour+monde"
  verifie legit "WP    installation" "${A[@]}" -d "weblog_title=Test+WAF&user_name=admin&admin_password=Adm1n!Pass_9x&admin_password2=Adm1n!Pass_9x&pw_weak=1&admin_email=a%40b.fr&Submit=Install+WordPress&language=" "$WP/wp-admin/install.php?step=2"
  verifie legit "WP    login admin" "${A[@]}" "${REF_LOGIN[@]}" -H "Cookie: wordpress_test_cookie=WP%20Cookie%20check" -d "log=admin&pwd=Adm1n!Pass_9x&wp-submit=Log+In&testcookie=1" "$WP/wp-login.php"
  verifie legit "WP    login utilisateur" "${A[@]}" -d "log=jean&pwd=azerty123&wp-submit=Log+In&testcookie=1" "$WP/wp-login.php"
  verifie legit "WP    commentaire" "${A[@]}" "${REF_ARTICLE[@]}" -d "comment=Merci+pour+larticle+$RANDOM&author=Jean&email=j%40example.com&url=&submit=Post+Comment&comment_post_ID=1&comment_parent=0" "$WP/wp-comments-post.php"
  verifie legit "Juice accueil" "${A[@]}" "$JUICE/"
  verifie legit "Juice recherche" "${A[@]}" "$JUICE/rest/products/search?q=apple"
  verifie legit "Juice login JSON" "${A[@]}" -H "Content-Type: application/json" -d '{"email":"jim@juice-sh.op","password":"ncc-1701"}' "$JUICE/rest/user/login"
  verifie legit "Juice avis JSON" "${A[@]}" -H "Content-Type: application/json" -d '{"UserId":1,"captchaId":3,"captcha":"12","comment":"Super boutique","rating":4}' "$JUICE/api/Feedbacks/"
done

echo "=== Attaques (403 attendu) ==="
verifie attaque "DVWA  SQLi" "$DVWA/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit"
verifie attaque "DVWA  XSS" "$DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E"
verifie attaque "DVWA  injection de commande" -d "ip=127.0.0.1;cat /etc/passwd&Submit=Submit" "$DVWA/vulnerabilities/exec/"
verifie attaque "DVWA  LFI" "$DVWA/vulnerabilities/fi/?page=../../../../etc/passwd"
verifie attaque "WP    SQLi (recherche)" "$WP/?s=1'+UNION+SELECT+user_pass+FROM+wp_users--"
verifie attaque "WP    XSS (commentaire)" -d "comment=%3Cscript%3Ealert(1)%3C/script%3E&author=x&email=x%40y.fr&submit=Post" "$WP/wp-comments-post.php"
verifie attaque "WP    SQLi (login)" -d "log=admin'--&pwd=x&wp-submit=Log+In" "$WP/wp-login.php"
verifie attaque "WP    scan .env" "$WP/.env"
verifie attaque "Juice SQLi (login JSON)" -H "Content-Type: application/json" -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}" "$JUICE/rest/user/login"
verifie attaque "Juice XSS (avis JSON)" -H "Content-Type: application/json" -d '{"UserId":1,"comment":"<script>alert(1)</script>","rating":1}' "$JUICE/api/Feedbacks/"
verifie attaque "Juice SQLi (recherche)" "$JUICE/rest/products/search?q='))+UNION+SELECT+sql+FROM+sqlite_master--"
verifie attaque "Juice LFI" "$JUICE/ftp/../../../etc/passwd"

echo
[ $ERREURS = 0 ] && echo "Tout est conforme." || echo "$ERREURS erreur(s)."
[ $ERREURS = 0 ]
