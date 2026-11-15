// SPDX-License-Identifier: Apache-2.0

// Valeurs publiques connues (écart d'analyse ajouté en v0.10.0, absent de Secret Guard ; UPSTREAM.md, « Code
// ordinaire ») : clés publiables, clés de site, jetons publics et clés d'essai que leur fournisseur fait écrire dans
// le code d'un client (navigateur, application mobile). Elles ne sont pas des secrets : sous un nom de clé ou de jeton,
// elles ne donnent ni constat d'affectation ni avertissement d'entropie.
//
// La liste des formes (motif de la valeur et, pour les formes sans préfixe propre, mots-clés du fournisseur) est
// reprise de Betterleaks, rules/generic/filter.go, testAndPublicAPIFilters (https://github.com/betterleaks/betterleaks,
// commit b4b1c4455987636400ce693bd9d8a8e2cf375ed9, Copyright (c) 2026 Zachary Rice, licence MIT ; avis dans NOTICE et
// UPSTREAM.md). Les motifs sont repris tels quels, ancrés aux deux bouts ; le code qui les applique est écrit pour ce
// module. Deux différences voulues :
//
//   - une forme à mot-clé n'est reconnue que si le mot-clé figure sur la ligne, avant la valeur (nom de la variable,
//     de la propriété ou de l'objet du fournisseur) ; un mot écrit après la valeur, en commentaire, ne compte pas ;
//   - les affectations ne l'appliquent qu'aux noms de clé d'API et de jeton, jamais à un mot de passe ni à un nom qui
//     porte « secret » (assignmentNoise).

package detect

import (
	"bytes"
	"regexp"
	"strings"
)

const publicUUID = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

// publicForm est une forme de valeur publique : motif de la valeur entière et mots-clés (en minuscules) dont l'un doit
// figurer sur la ligne avant elle ; sans mot-clé, le motif suffit.
type publicForm struct {
	pattern  string
	keywords []string
}

// publicForms : formes reprises de Betterleaks (voir l'en-tête), dans leur ordre d'origine. Les deux valeurs fixes de
// la fin de la première série (clés publiques d'exemples connus) sont assemblées par morceaux.
var publicForms = []publicForm{
	// Motif seul.
	{pattern: `sb_publishable_[A-Za-z0-9_-]{31}`},                                         // Supabase, clé publiable
	{pattern: `0x4AAAAAA[A-Za-z0-9_-]{15}`},                                               // Cloudflare Turnstile, clé de site
	{pattern: `FCM[a-zA-Z0-9]{13}`},                                                       // Friendly Captcha, clé de site
	{pattern: `ysc1_[A-Za-z0-9_-]{48}`},                                                   // Yandex SmartCaptcha, clé de site
	{pattern: `phc_[A-Za-z0-9_-]{43,44}`},                                                 // PostHog, clé de projet
	{pattern: `APP_USR-` + publicUUID},                                                    // Mercado Pago, clé publique de production
	{pattern: `access-(sandbox|development)-` + publicUUID},                               // Plaid, jeton d'accès d'essai
	{pattern: `asset-report-(sandbox|development)-` + publicUUID},                         // Plaid, jeton de rapport d'essai
	{pattern: `public-(sandbox|development|production)-` + publicUUID},                    // Plaid, jeton public
	{pattern: `link-(sandbox|development)-` + publicUUID},                                 // Plaid, jeton de lien d'essai
	{pattern: `hbp_[0-9a-zA-Z]{36}`},                                                      // Honeybadger
	{pattern: `woos-` + publicUUID},                                                       // Woosmap, clé publique
	{pattern: `(https://)?[0-9a-zA-Z]{32}@sentry\.io`},                                    // Sentry, DSN public
	{pattern: `sub-c-` + publicUUID},                                                      // PubNub, clé d'abonnement
	{pattern: `pub-c-` + publicUUID},                                                      // PubNub, clé de publication
	{pattern: `hc[a-z]ik_([a-z0-9]{26,58})`},                                              // Honeycomb, clé d'ingestion
	{pattern: `mob-` + publicUUID},                                                        // LaunchDarkly, clé mobile
	{pattern: `public-token-test-` + publicUUID},                                          // Stytch, jeton public d'essai
	{pattern: `public-token-live-` + publicUUID},                                          // Stytch, jeton public
	{pattern: `pdl_sdbx_apikey_[a-z\d]{26}_[a-zA-Z\d]{22}_[a-zA-Z\d]{3}`},                 // Paddle, clé d'essai
	{pattern: strings.Join([]string{"8c680316", "4dbc395f", "b7131c9d", "54843627"}, "")}, // Flickr dans Dojo Toolkit (désactivée)
	{pattern: strings.Join([]string{"6fe4476e", "e5a18328", "82e326b5", "06d14126"}, "")}, // clé publique d'exemple
	// Motif et mot-clé sur la ligne.
	{`pk_test_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe", "woo", "wcm"}}, // Stripe, WooCommerce : clé publiable d'essai
	{`rk_test_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe"}},               // Stripe, clé restreinte d'essai
	{`pk_live_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe", "woo", "wcm"}}, // Stripe, WooCommerce : clé publiable
	{`pk_test_[A-Za-z0-9_-]{40}`, []string{"paystack"}},                                                   // Paystack, clé publique d'essai
	{`pk_live_[A-Za-z0-9_-]{40}`, []string{"paystack"}},                                                   // Paystack, clé publique
	{`sandbox_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{16}`, []string{"braintree"}},                                   // Braintree, clé d'essai
	{`production_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{16}`, []string{"braintree"}},                                // Braintree, clé de production
	{`test_[0-9a-zA-Z]{32}`, []string{"adyen"}},                                                           // Adyen, clé de client d'essai
	{`live_[0-9a-zA-Z]{32}`, []string{"adyen"}},                                                           // Adyen, clé de client
	{`[A-Za-z0-9]{32}`, []string{"bugsnag"}},                                                              // Bugsnag, clé du SDK
	{publicUUID, []string{"hcaptcha", "site_key", "sitekey"}},                                             // hCaptcha, clé de site
	{publicUUID, []string{"pendo"}},                                                                       // Pendo
	{publicUUID, []string{"instrumentation"}},                                                             // Azure Application Insights
	{`TEST-` + publicUUID, []string{"mercado"}},                                                           // Mercado Pago, clé publique d'essai
	{`[0-9a-fA-F]{32}`, []string{"mixpanel"}},                                                             // Mixpanel, jeton de projet
	{`[0-9a-z]{6}/[a-z_-]{2,100}`, []string{"logrocket"}},                                                 // LogRocket, identifiant de projet
	{`[0-9a-f]{8}`, []string{"honeybadger"}},                                                              // Honeybadger, jeton de contrôle
	{`[a-zA-Z0-9=+]{21,24}`, []string{"raygun"}},                                                          // Raygun
	{`key_live_[0-9a-zA-Z]{32}`, []string{"branch"}},                                                      // Branch.io
	{`key_test_[0-9a-zA-Z]{32}`, []string{"branch"}},                                                      // Branch.io, essai
	{`pub[0-9a-zA-Z]{32}`, []string{"datadog", "dd"}},                                                     // Datadog, jeton de client
	{`[0-9a-zA-Z]{6}`, []string{"klaviyo"}},                                                               // Klaviyo, identifiant de société
	{`[0-9a-zA-Z]{32}`, []string{"storefront"}},                                                           // Shopify Storefront, jeton public
	{`search-[0-9a-zA-Z_-]{24}`, []string{"swiftype"}},                                                    // Elastic Swiftype, clé de recherche
	{`[0-9a-zA-Z_-]{20}`, []string{"swiftype"}},                                                           // Elastic Swiftype, clé de moteur
	{`pk.eyJ1Ijoi[0-9a-zA-Z_-]{1,}\.[0-9a-zA-Z-_]{1,}`, []string{"map"}},                                  // Mapbox, jeton public
	{publicUUID, []string{"crisp"}},                                                                       // Crisp
	{`client-[a-zA-Z0-9]{43}`, []string{"statsdig"}},                                                      // Statsdig
	{`sdk-[a-zA-Z0-9]{15,16}`, []string{"growthbook"}},                                                    // GrowthBook, clé de client
	{`[a-zA-Z0-9/=]{24}`, []string{"growthbook"}},                                                         // GrowthBook, clé de déchiffrement
	{`[a-zA-Z0-9]{21,22}`, []string{"optimizely"}},                                                        // Optimizely, clé du SDK
	{`[0-9a-fA-F]{24}`, []string{"launchdarkly"}},                                                         // LaunchDarkly, identifiant côté client
	{`pk_test_[0-9a-zA-Z]{20,70}`, []string{"clerk"}},                                                     // Clerk, clé publiable d'essai
	{`pk_live_[0-9a-zA-Z]{20,70}`, []string{"clerk"}},                                                     // Clerk, clé publiable
	{`[0-9a-zA-Z]{40}`, []string{"smartlook"}},                                                            // Smartlook
	{`[0-9A-Z]{5,6}`, []string{"fullstory"}},                                                              // FullStory, identifiant d'organisation
	{publicUUID, []string{"zendesk", "zdassets.com"}},                                                     // Zendesk, clé du widget
	{`[0-9a-zA-Z]{27}`, []string{"rudderstack"}},                                                          // RudderStack, clé d'écriture
	{publicUUID, []string{"web3forms"}},                                                                   // Web3Forms
	{`[0-9]{12}`, []string{"2checkout", "twocheckout"}},                                                   // 2Checkout, code marchand
	{`test_[a-zA-Z0-9]{27}`, []string{"paddle"}},                                                          // Paddle, jeton d'essai côté client
	{`live_[a-zA-Z0-9]{27}`, []string{"paddle"}},                                                          // Paddle, jeton côté client
	{`pk_live_[0-9A-F]{16}`, []string{"magic"}},                                                           // Magic, clé publiable
}

// compiledPublicForm : forme prête à l'emploi.
type compiledPublicForm struct {
	pattern  *regexp.Regexp
	keywords [][]byte
}

var (
	// publicPlain : formes sans mot-clé, en une seule alternative.
	publicPlain *regexp.Regexp
	// publicKeyed : formes à mot-clé.
	publicKeyed []compiledPublicForm
)

func init() {
	var plain []string
	for _, form := range publicForms {
		if len(form.keywords) == 0 {
			plain = append(plain, form.pattern)
			continue
		}
		compiled := compiledPublicForm{pattern: regexp.MustCompile(`^(?:` + form.pattern + `)$`)}
		for _, keyword := range form.keywords {
			compiled.keywords = append(compiled.keywords, []byte(keyword))
		}
		publicKeyed = append(publicKeyed, compiled)
	}
	publicPlain = regexp.MustCompile(`^(?:` + strings.Join(plain, "|") + `)$`)
}

const (
	// publicValueMax : plus longue valeur publique (clé publiable de 107 caractères, jeton Mapbox) ; au-delà, la valeur
	// n'est pas comparée.
	publicValueMax = 512
	// publicLineBytes : octets de la ligne lus avant la valeur pour y chercher un mot-clé.
	publicLineBytes = 512
)

// isPublicValue dit si text[start:end] est une valeur publique connue (publicForms). La valeur est comparée telle
// quelle, puis étendue aux lettres, chiffres, « . », « _ » et « - » qui la touchent : le candidat d'entropie d'un
// jeton à points n'en est qu'un morceau. Un DSN de Sentry est reconnu à l'hôte qui suit sa clé. Les mots-clés sont
// cherchés, sans tenir compte de la casse, sur la ligne avant la valeur.
func isPublicValue(text []byte, start, end int) bool {
	if start < 0 || end > len(text) || start >= end || end-start > publicValueMax {
		return false
	}
	if matchesPublicForm(text, start, end) {
		return true
	}
	wideStart, wideEnd := start, end
	for wideStart > 0 && start-wideStart < publicValueMax && isPublicTokenByte(text[wideStart-1]) {
		wideStart--
	}
	for wideEnd < len(text) && wideEnd-end < publicValueMax && isPublicTokenByte(text[wideEnd]) {
		wideEnd++
	}
	// Clé d'un DSN de Sentry : « clé@sentry.io ».
	if bytes.HasPrefix(text[wideEnd:], []byte("@sentry.io")) && publicPlain.Match(append(append([]byte(nil), text[wideStart:wideEnd]...), "@sentry.io"...)) {
		return true
	}
	if wideStart == start && wideEnd == end {
		return false
	}
	return wideEnd-wideStart <= publicValueMax && matchesPublicForm(text, wideStart, wideEnd)
}

func isPublicTokenByte(c byte) bool {
	return isASCIIAlphanumeric(c) || c == '.' || c == '_' || c == '-'
}

// matchesPublicForm compare text[start:end] aux formes : sans mot-clé d'abord, puis celles dont un mot-clé figure sur
// la ligne avant start.
func matchesPublicForm(text []byte, start, end int) bool {
	value := text[start:end]
	if publicPlain.Match(value) {
		return true
	}
	lineStart := start
	for lineStart > 0 && start-lineStart < publicLineBytes && text[lineStart-1] != '\n' && text[lineStart-1] != '\r' {
		lineStart--
	}
	if lineStart == start {
		return false
	}
	before := bytes.ToLower(text[lineStart:start])
	for _, form := range publicKeyed {
		for _, keyword := range form.keywords {
			if bytes.Contains(before, keyword) {
				if form.pattern.Match(value) {
					return true
				}
				break
			}
		}
	}
	return false
}
