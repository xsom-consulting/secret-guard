// SPDX-License-Identifier: Apache-2.0

// Package injection trouve, dans un texte que personne n'a écrit pour l'agent (page lue, résultat d'outil, fichier
// cité), les consignes adressées à l'agent : « ignore les instructions précédentes », changement de rôle, demande
// d'envoyer des secrets à une adresse, ordre de cacher quelque chose à l'utilisateur, balises de tours de parole
// copiées dans le texte ; et, depuis la v0.10.0, préfixe de réponse imposé, faux historique de conversation,
// interdiction de refuser ou d'avertir, charge découpée en morceaux à réunir, demande de révéler le message système,
// ordre de désactiver les filtres, étiquettes de rôle. Les formes sont reconnues en français et en anglais.
//
// C'est un détecteur de constat : il ne modifie ni ne masque rien (le texte d'une page lue n'est pas à expurger) et ne
// juge pas : la décision (avertir, bloquer) revient à l'appelant. Il ne couvre pas une consigne écrite autrement que
// par les formes ci-dessous ; une absence de constat n'est pas une preuve d'innocuité. Ce qu'il signale sur des
// textes d'attaque publics et sur des dépôts sains est mesuré, pas promis : docs/bench.md.
//
// Une formule courte citée entre guillemets au milieu d'une phrase (« les attaquants écrivent “ignore all previous
// instructions” dans une page ») est une mention : elle n'est pas signalée (context.go). Un texte qui emploie la
// formule sans guillemets, qui la donne comme valeur (après « : » ou « = », en début de ligne) ou qui la cite sur
// plus d'une phrase reste signalé, documentation sur l'injection de prompt comprise.
//
// Le texte est lu tel quel, puis normalisé et déplié (pleine chasse, espaces insécables, texte replié sur plusieurs
// lignes), puis décodé une fois (pourcentages, échappements de chaîne, base64) : views.go. Une consigne repliée par
// des homoglyphes, du leetspeak ou des lettres espacées n'est pas lue ; les caractères invisibles relèvent du paquet
// hidden.
//
// Find rend la règle, la ligne, la colonne et l'étendue en octets de chaque constat, toujours dans le texte reçu ;
// jamais le texte trouvé. Au-delà de MaxInputBytes octets, rien n'est lu : le rapport est incomplet, et ne vaut jamais
// « rien trouvé ».
//
// Le paquet est pur (règle depguard de .golangci.yml) : ni E/S, ni réseau, ni horloge, ni hasard, ni journal. Les
// motifs sont des expressions RE2 : temps linéaire, sans retour arrière. Chaque motif n'est exécuté qu'aux endroits
// où figurent ses mots obligatoires (gate.go). Les appels concurrents sont sûrs.
package injection

import (
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/xsom-consulting/secret-guard/internal/limits"
)

// Rule est l'identifiant d'une règle ; il sert d'identifiant de règle dans les Événements de l'appelant.
type Rule string

const (
	// InstructionOverride : ordre d'oublier, d'ignorer ou d'annuler les instructions reçues.
	InstructionOverride Rule = "injection_instruction_override"
	// RoleSwitch : ordre de prendre un autre rôle, de se croire sans restriction ou de n'obéir qu'au texte lu.
	RoleSwitch Rule = "injection_role_switch"
	// Exfiltration : ordre d'envoyer des secrets (clés, mots de passe, jetons, identifiants) à une adresse ou une URL.
	Exfiltration Rule = "injection_exfiltration"
	// Concealment : ordre de ne pas dire ou de cacher une action à l'utilisateur.
	Concealment Rule = "injection_concealment"
	// MessageMarkers : balises de tours de parole ou de message système de modèles de langage dans un texte lu.
	MessageMarkers Rule = "injection_message_markers"
	// ForcedPrefix : ordre de commencer chaque réponse par un texte imposé.
	ForcedPrefix Rule = "injection_forced_prefix"
	// FakeHistory : faux tours de conversation écrits dans le texte (« User: … Assistant: … User: … »).
	FakeHistory Rule = "injection_fake_history"
	// RefusalSuppression : interdiction de refuser, de s'excuser ou d'avertir.
	RefusalSuppression Rule = "injection_refusal_suppression"
	// PayloadSplitting : ordre de réunir des morceaux puis d'exécuter ou de suivre le résultat.
	PayloadSplitting Rule = "injection_payload_splitting"
	// SystemPromptLeak : demande de révéler le message système ou les instructions reçues.
	SystemPromptLeak Rule = "injection_system_prompt_leak"
	// FilterDisable : ordre de désactiver les filtres ou d'entrer dans un mode sans restriction.
	FilterDisable Rule = "injection_filter_disable"
	// RoleLabels : étiquettes de rôle écrites dans le texte (ligne « system: » suivie d'un ordre d'annulation, bloc
	// « ```system », « --- » puis « system: », jeton </s>).
	RoleLabels Rule = "injection_role_labels"
)

// Rules sont les règles, dans l'ordre où Find les applique.
func Rules() []Rule {
	return []Rule{InstructionOverride, RoleSwitch, Exfiltration, Concealment, MessageMarkers,
		ForcedPrefix, FakeHistory, RefusalSuppression, PayloadSplitting, SystemPromptLeak, FilterDisable, RoleLabels}
}

const (
	// MaxInputBytes est la taille de texte la plus grande lue, en octets reçus (celle du moteur de détection, 1 Mio).
	MaxInputBytes = limits.MaxInputBytes
	// MaxFindings est le nombre de constats gardés dans un rapport ; Report.Total reste exact au-delà.
	MaxFindings = 50
)

// Finding est un constat. Son texte n'est jamais rendu.
type Finding struct {
	Rule Rule
	// Line est la ligne (à partir de 1, fins de ligne « \n ») du début du constat.
	Line int
	// Column est la colonne (à partir de 1), en points de code, du début du constat.
	Column int
	// ByteStart et ByteEnd bornent le constat dans le texte reçu, en octets (fin exclue). Pour une consigne trouvée dans
	// un bloc base64, c'est le bloc entier.
	ByteStart int
	ByteEnd   int
}

// Report est le résultat de Find.
type Report struct {
	// Complete est faux au-delà de MaxInputBytes (le texte n'est pas lu) et quand une lecture dérivée dépasse sa borne
	// (texte dont la forme normalisée est démesurée) : le texte ne doit pas être tenu pour propre.
	Complete bool
	// Total est le nombre exact de constats, même au-delà de ceux gardés.
	Total int
	// Findings sont les constats, dans l'ordre du texte, au plus MaxFindings.
	Findings []Finding
}

// Un motif ne traverse jamais une fin de phrase ni de ligne : [^.\n] borne l'intervalle entre ses mots-clés.
// Les mots sont cherchés sans casse ; les lettres accentuées sont écrites en classes ([eé]) pour tolérer l'absence
// d'accent. Aucune borne de mot \b après une lettre accentuée (\b de RE2 ne connaît que l'ASCII).
var patternSources = []struct {
	rule   Rule
	source string
	// before est un motif de contexte facultatif (context.go), cherché juste avant la correspondance sur sa ligne.
	// beforeRequired : il doit s'y trouver ; sinon il ne doit pas s'y trouver.
	before         string
	beforeRequired bool
}{
	// Annulation des instructions : verbe d'annulation, puis « précédentes / ci-dessus / toutes », puis le nom.
	{rule: InstructionOverride, source: `(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|all|any|your)\b[^.\n]{0,30}?\b(?:instructions?|prompts?|rules?|directions?|guidelines?|constraints?)\b`},
	{rule: InstructionOverride, source: `(?i)\b(?:do not|don't|never)\s+follow\b[^.\n]{0,40}?\b(?:instructions?|rules?|guidelines?)\b`},
	{rule: InstructionOverride, source: `(?i)\b(?:ignore[rz]?|oublie[rz]?|annule[rz]?|n[eé]glige[rz]?|contourne[rz]?|passe[rz]? outre)\b[^.\n]{0,40}?\b(?:pr[eé]c[eé]dent|ant[eé]rieur|ci-dessus|toutes?|tes|vos|les)\b[^.\n]{0,30}?\b(?:instructions?|consignes?|directives?|r[eè]gles?|prompts?|contraintes?)\b`},
	{rule: InstructionOverride, source: `(?i)\bne (?:tiens?|tenez|suis|suivez)\s+(?:pas|plus)\b[^.\n]{0,40}?\b(?:instructions?|consignes?|directives?|r[eè]gles?)\b`},

	// Changement de rôle : nouveau rôle explicite, ou obéissance exclusive au texte lu.
	{rule: RoleSwitch, source: `(?i)\byou are now\b[^.\n]{0,20}?\b(?:an?|the|in)\b[^.\n]{0,30}?\b(?:assistant|agent|ai|model|bot|dan|unrestricted|jailbroken|developer mode)\b`},
	{rule: RoleSwitch, source: `(?i)\bfrom now on\b[^.\n]{0,12}\byou (?:will|must|shall|are to)\b[^.\n]{0,25}?\b(?:ignore|obey|follow|only|always|never|act|respond|answer|reply)\b`},
	{rule: RoleSwitch, source: `(?i)\b(?:pretend|act as if) (?:that )?you (?:are|have no|can|were)\b[^.\n]{0,40}?\b(?:unrestricted|restrictions?|rules?|limits?|filters?|jailbroken|different|another)\b`},
	{rule: RoleSwitch, source: `(?i)\b(?:new|updated|real) (?:system )?(?:instructions?|prompt)\s*:`},
	{rule: RoleSwitch, source: `(?i)\b(?:tu es|vous [eê]tes) (?:maintenant|d[eé]sormais)\b[^.\n]{0,20}?\b(?:un|une|le|la|en)\b[^.\n]{0,30}?\b(?:assistant|agent|ia|mod[eè]le|bot|dan|sans restriction|sans limite|mode d[eé]veloppeur)\b`},
	{rule: RoleSwitch, source: `(?i)\bd[eé]sormais,?\s+(?:tu|vous)\s+(?:dois|devez|vas|allez|ne dois|ne devez)\b[^.\n]{0,25}?\b(?:ignorer|ob[eé]ir|suivre|toujours|jamais|uniquement|seulement|agir|r[eé]pondre)\b`},
	{rule: RoleSwitch, source: `(?i)\b(?:fais|faites) (?:semblant|comme si)\b[^.\n]{0,40}?\b(?:sans restriction|sans limite|sans r[eè]gle|aucune restriction|aucune r[eè]gle)\b`},
	{rule: RoleSwitch, source: `(?i)\bnouvelles? (?:instructions?|consignes?)\s*:`},

	// Exfiltration : verbe d'envoi, un secret, puis une adresse (URL ou courriel).
	{rule: Exfiltration, source: `(?i)\b(?:send|post|upload|forward|exfiltrate|email|e-mail|transmit|leak|curl)\b[^.\n]{0,60}?\b(?:secrets?|credentials?|passwords?|api[ _-]?keys?|access[ _-]?tokens?|tokens?|private keys?|ssh keys?|\.env)\b[^\n]{0,80}?(?:https?://|[\w.+-]+@[\w-]+\.[\w.-]+)`},
	{rule: Exfiltration, source: `(?i)\b(?:envoie[rz]?|transmets?|transmettez|poste[rz]?|exfiltre[rz]?|t[eé]l[eé]verse[rz]?|copie[rz]?)\b[^.\n]{0,60}?\b(?:secrets?|identifiants?|mots? de passe|cl[eé]s?|jetons?|\.env)\b[^\n]{0,80}?(?:https?://|[\w.+-]+@[\w-]+\.[\w.-]+)`},

	// Dissimulation à l'utilisateur.
	{rule: Concealment, source: `(?i)\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify|alert)\b[^.\n]{0,20}?\b(?:the )?user\b`},
	{rule: Concealment, source: `(?i)\bwithout (?:telling|informing|notifying|alerting)\b[^.\n]{0,15}?\b(?:the )?user\b`},
	{rule: Concealment, source: `(?i)\bne (?:le |la |lui |en )?(?:dis|dites|dire|montre|montrez|r[eé]v[eè]le|r[eé]v[eé]lez|signale|signalez|informe|informez|pr[eé]viens|pr[eé]venez)\b[^.\n]{0,25}?\b(?:pas|jamais)\b[^.\n]{0,20}?(?:[aà] l'?utilisateur|[aà] l'?op[eé]rateur)\b`},
	{rule: Concealment, source: `(?i)\bsans (?:en )?(?:informer|pr[eé]venir|alerter|avertir)\b[^.\n]{0,15}?\bl'?utilisateur\b`},
	{rule: Concealment, source: `(?i)\b(?:hide|conceal|withhold)\b[^.\n]{0,30}?\b(?:actions?|steps?|instructions?|operations?|activit(?:y|ies)|behaviou?rs?|changes?|commands?|requests?)\b[^.\n]{0,25}?\bfrom (?:the )?users?\b`},
	{rule: Concealment, source: `(?i)\b(?:cache[rz]?|dissimule[rz]?|masque[rz]?)\b[^.\n]{0,30}?(?:\b(?:actions?|instructions?|op[eé]rations?|commandes?|modifications?|changements?)|[eé]tapes?)\b[^.\n]{0,25}?[aà] l'?utilisateur\b`},

	// Balises de tours de parole et de message système : jetons spéciaux de modèles, jamais du texte ordinaire.
	{rule: MessageMarkers, source: `(?i)<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>`},
	{rule: MessageMarkers, source: `(?i)\[/?INST\]|<<\s*/?SYS\s*>>`},

	// Préfixe imposé : verbe d'ouverture, « ta / chaque réponse », puis « par / with ».
	{rule: ForcedPrefix, source: `(?i)\b(?:start|begin|open|prefix|preface)\b[^.\n]{0,25}?\b(?:your|each|every|all)\b[^.\n]{0,25}?\b(?:responses?|repl(?:y|ies)|answers?|outputs?|messages?)\b[^.\n]{0,20}?\b(?:with|by)\b`},
	{rule: ForcedPrefix, source: `(?i)\b(?:commence[rz]?|d[eé]bute[rz]?|pr[eé]fixe[rz]?)\b[^.\n]{0,25}?\b(?:ta|tes|votre|vos|chaque|chacune|toutes?)\b[^.\n]{0,25}?\br[eé]ponses?\b[^.\n]{0,20}?\b(?:par|avec)\b`},

	// Faux historique : trois tours qui alternent, chacun en début de ligne.
	{rule: FakeHistory, source: `(?im)^(?:user|human|utilisateur|humain)\s?:[^\n]{1,300}\n{1,2}(?:assistant|ai|bot|chatgpt|claude|gpt)\s?:[^\n]{1,300}\n{1,2}(?:user|human|utilisateur|humain)\s?:`},

	// Suppression du refus : interdiction de refuser ou de s'excuser, réponse exigée sans avertissement.
	{rule: RefusalSuppression, source: `(?i)\b(?:do not|don't|never|cannot|can't|can not|must not|mustn't|should not|shouldn't|will not|won't)\s+(?:ever\s+)?(?:refuse|decline|apologi[sz]e)\b`},
	{rule: RefusalSuppression, source: `(?i)\b(?:answer|respond|reply|comply|responses?|replies|answers?)\b[^.\n]{0,40}?\bwithout (?:any |any kind of )?(?:warnings?|disclaimers?|refusing|refusals?|apolog\w+|morali\w+|censor\w+|caveats?)\b`},
	{rule: RefusalSuppression, source: `(?i)\b(?:do not|don't|never)\s+(?:include|add|give|provide|write|mention|use)\b[^.\n]{0,20}?\b(?:warnings?|disclaimers?|caveats?|apolog(?:y|ies))\b`},
	{rule: RefusalSuppression, source: `(?i)\bne (?:refuse[sz]?|t'excuse[sz]?|vous excusez|d[eé]cline[sz]?)\s+(?:jamais|pas|plus)\b`},
	{rule: RefusalSuppression, source: `(?i)\b(?:r[eé]ponds?|r[eé]pondez|r[eé]pondre|r[eé]ponses?)\b[^.\n]{0,40}?\bsans (?:aucun |aucune |le moindre |la moindre )?(?:avertissement|refus|excuse|morale|censure|mise en garde)s?\b`},

	// Découpage : réunir des morceaux, puis exécuter ou suivre le résultat.
	{rule: PayloadSplitting, source: `(?i)\b(?:concatenate|combine|join|merge|assemble|put together|piece together)\b[^.\n]{0,30}?\b(?:strings?|parts?|pieces?|fragments?|chunks?|segments?)\b[^.\n]{0,40}?\b(?:and|then|to)\b[^.\n]{0,20}?\b(?:follow|execute|run|obey|perform|comply|carry out)\b`},
	{rule: PayloadSplitting, source: `(?i)\b(?:concat[eè]ne[rz]?|assemble[rz]?|r[eé]unis(?:sez)?|r[eé]unir|recolle[rz]?|mets bout [aà] bout|mettez bout [aà] bout)\b[^.\n]{0,30}?\b(?:cha[iî]nes?|morceaux|parties?|fragments?|segments?)\b[^.\n]{0,40}?\b(?:puis|et|pour)\b[^.\n]{0,20}?\b(?:ex[eé]cute[rz]?|sui[stv]\w*|applique[rz]?|ob[eé]i[rstz]\w*)`},

	// Message système : demande de le révéler. Une négation juste avant (« never reveal… », « ne révèle jamais… »)
	// en fait une défense : la correspondance est écartée.
	{rule: SystemPromptLeak, source: `(?i)\b(?:reveal|show|print|output|display|repeat|leak|disclose|share|recite|expose|dump|tell me|give me|write out|return)\b[^.\n]{0,25}?\b(?:your (?:system |initial |original |hidden |secret |internal |full |exact |own )?(?:system message|system prompt|prompt|instructions?)|the (?:prompt|instructions?) above|the above (?:prompt|instructions?))\b`,
		before: `(?i)(?:\b(?:not|never|cannot|without|avoid|refuse to|don.t|doesn.t|won.t|can.t|shouldn.t|mustn.t)|n't)\s+(?:\w+\s+){0,2}$`},
	{rule: SystemPromptLeak, source: `(?i)\bwhat (?:are|is|were|was) your (?:system |initial |original |exact |hidden )?(?:instructions?|system prompt|prompt|directives?)\b`},
	{rule: SystemPromptLeak, source: `(?i)\b(?:repeat|print|output|write)\b[^.\n]{0,15}?\b(?:everything|all|the words?|the text)\b[^.\n]{0,15}?\b(?:above|before)\b`},
	{rule: SystemPromptLeak, source: `(?i)\b(?:r[eé]v[eè]le[rz]?|affiche[rz]?|montre[rz]?|r[eé]p[eè]te[rz]?|donne[rz]?|imprime[rz]?|divulgue[rz]?|recopie[rz]?|cite[rz]?)\b[^.\n]{0,30}?\b(?:prompt syst[eè]me|message syst[eè]me|instructions? (?:syst[eè]me|initiales?|d'origine|cach[eé]es?)|prompt (?:initial|d'origine|cach[eé])|consignes? (?:syst[eè]me|initiales?|d'origine|cach[eé]es?))`,
		before: `(?i)(?:\bne|\bn'|\bsans|\bjamais)\s*(?:\w+\s+){0,2}$`},
	{rule: SystemPromptLeak, source: `(?i)\bquelles? (?:sont|est|[eé]taient) (?:tes|vos|ton|votre) (?:instructions?|consignes?|prompt)\b`},

	// Filtres : ordre de les désactiver, mode sans restriction, affranchissement d'une politique de contenu.
	{rule: FilterDisable, source: `(?i)\b(?:disable|deactivate|turn off|switch off|remove|bypass|circumvent|lift|drop)\b[^.\n]{0,25}?\b(?:safety|content|ethical|moral|moderation|censorship)\b[^.\n]{0,15}?\b(?:filters?|guidelines?|guardrails?|restrictions?|polic(?:y|ies))\b`},
	{rule: FilterDisable, source: `(?i)\b(?:enter|enable|activate|switch to|you are in|you are now in)\b[^.\n]{0,15}?\b(?:jailbreak|unrestricted|uncensored|unfiltered|dan|god)[ -]mode\b`},
	{rule: FilterDisable, source: `(?i)\b(?:bound by|restricted by|constrained by|abide by|adhere to|comply with)\b[^.\n]{0,25}?\b(?:content polic(?:y|ies)|safety guidelines|ethical guidelines|usage polic(?:y|ies)|openai(?:'s)? (?:polic(?:y|ies)|rules|guidelines|content))\b`,
		before: `(?i)(?:\b(?:not|never|no longer|without having to|free to not)|n't)\s+(?:\w+\s+){0,3}$`, beforeRequired: true},
	{rule: FilterDisable, source: `(?i)\b(?:d[eé]sactive[rz]?|coupe[rz]?|retire[rz]?|supprime[rz]?|contourne[rz]?|l[eè]ve[rz]?)\b[^.\n]{0,25}?\b(?:filtres?|garde-fous?|restrictions?|protections?|mod[eé]ration)\b[^.\n]{0,15}?(?:\b(?:de s[eé]curit[eé]|de contenu|de mod[eé]ration|morales?)|[eé]thiques?)`},
	{rule: FilterDisable, source: `(?i)\bmode (?:sans restriction|sans filtre|sans censure|d[eé]brid[eé]|jailbreak)`},

	// Étiquettes de rôle : ligne « system: » suivie d'un ordre d'annulation, bloc de code « system », fin de séquence.
	{rule: RoleLabels, source: `(?i)system(?: (?:prompt|message|instructions?|note|override))?\]?\*{0,2}\s?:\s?\*{0,2}\s?(?:ignore|forget|override|disregard|from now on|new instructions|oublie|d[eé]sormais)`,
		before: `^[ \t>*#\[|-]{0,8}$`, beforeRequired: true},
	{rule: RoleLabels, source: "(?i)```\\s?system\\b"},
	{rule: RoleLabels, source: `(?i)---[ \t]*\r?\n[ \t]*system\s?:`},
	{rule: RoleLabels, source: `(?i)</s>`, before: `(?i)<s>[^<\n]*$`},
}

// patterns sont les motifs compilés, dans l'ordre de patternSources ; engine est leur porte littérale (gate.go).
var (
	patterns = func() []pattern {
		compiled := make([]pattern, 0, len(patternSources))
		for _, p := range patternSources {
			pattern := compilePattern(p.rule, p.source)
			if p.before != "" {
				pattern.before, pattern.beforeRequired = regexp.MustCompile(p.before), p.beforeRequired
			}
			compiled = append(compiled, pattern)
		}
		return compiled
	}()
	engine = newGate(patterns)
)

func positions(text []byte, start int, line, column *int, from int) {
	for off := from; off < start; {
		r, width := utf8.DecodeRune(text[off:])
		if r == '\n' {
			*line++
			*column = 1
		} else {
			*column++
		}
		off += width
	}
}

// match est une correspondance d'un motif, ramenée aux octets de la source.
type match struct {
	rule       Rule
	start, end int
	// order est le rang du motif ; view celui de la lecture qui l'a trouvée (0 : le texte tel quel).
	order, view int
}

// Find rend les constats du texte, dans l'ordre du texte (à début égal, dans l'ordre des règles). Les motifs sont
// cherchés dans le texte tel quel et dans ses autres lectures (views.go) : normalisé, déplié, décodé une fois. Une
// règle ne rend qu'un constat pour des étendues qui se recouvrent, quelle que soit la lecture qui les a trouvées.
//
// Au-delà de MaxInputBytes octets, rien n'est lu : Complete est faux, Total vaut 0 et Findings est vide. Complete est
// faux aussi quand une lecture dépasse sa borne (maxViewBytes) : les constats des autres lectures sont rendus, et le
// texte ne doit pas être tenu pour propre.
func Find(text []byte) Report {
	return find(text, engine.scan)
}

// find applique scanView à chaque lecture du texte et réunit les constats. scanView est la porte littérale ; les
// tests y mettent une recherche sans porte pour prouver que le résultat est le même.
func find(text []byte, scanView func(patterns []pattern, v *view, yield func(pattern, start, end int))) Report {
	if len(text) > MaxInputBytes {
		return Report{}
	}
	report := Report{Complete: true}
	var found []match
	views := 0
	scan := func(v *view) {
		rank := views
		views++
		scanView(patterns, v, func(order, start, end int) {
			sourceStart, sourceEnd := v.source(start, end)
			found = append(found, match{patterns[order].rule, sourceStart, sourceEnd, order, rank})
		})
	}
	// read lit une vue, puis sa forme normalisée, puis sa forme normalisée et dépliée, quand elles en diffèrent. Les
	// deux sont lues : une règle définie par ses lignes (faux historique, étiquette de rôle en début de ligne) ne se
	// retrouve que dans la première, une consigne repliée que dans la seconde.
	read := func(v *view) {
		forms, ok := foldedForms(v)
		if !ok {
			report.Complete = false
		}
		scan(v)
		for _, form := range forms {
			form.afterDecoding = v.segs != nil
			scan(form)
		}
	}
	source := &view{text: text}
	read(source)
	for _, decode := range []func(*view) (*view, bool){decodedOnce, base64Decoded} {
		decoded, ok := decode(source)
		if !ok {
			report.Complete = false
		}
		if decoded != nil {
			read(decoded)
		}
	}
	sort.Slice(found, func(i, j int) bool {
		a, b := found[i], found[j]
		switch {
		case a.start != b.start:
			return a.start < b.start
		case a.order != b.order:
			return a.order < b.order
		case a.view != b.view:
			return a.view < b.view
		default:
			return a.end < b.end
		}
	})
	line, column, at := 1, 1, 0
	// previousEnd est, par règle, la fin du dernier constat gardé : deux motifs de la même règle sur la même étendue,
	// ou la même consigne vue par deux lectures, ne font qu'un constat.
	previousEnd := map[Rule]int{}
	for _, m := range found {
		if end, seen := previousEnd[m.rule]; seen && m.start < end {
			continue
		}
		previousEnd[m.rule] = m.end
		positions(text, m.start, &line, &column, at)
		at = m.start
		report.Total++
		if len(report.Findings) < MaxFindings {
			report.Findings = append(report.Findings, Finding{Rule: m.rule, Line: line, Column: column, ByteStart: m.start, ByteEnd: m.end})
		}
	}
	return report
}
