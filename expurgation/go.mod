module github.com/xsom-consulting/secret-guard/expurgation

go 1.27.2

require github.com/xsom-consulting/secret-guard v0.7.0

require golang.org/x/text v0.43.0 // indirect

// Développement dans ce dépôt : le moteur (Apache-2.0) est le module racine, un dossier plus haut. Sans effet pour qui
// importe ce module : seule la version exigée ci-dessus compte alors (étiquette du module racine).
replace github.com/xsom-consulting/secret-guard => ../
