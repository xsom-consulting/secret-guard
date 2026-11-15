// SPDX-License-Identifier: Apache-2.0

// Package injection trouve, dans un texte que personne n'a écrit pour l'agent (page lue, résultat d'outil, fichier
// cité), les consignes adressées à l'agent : « ignore les instructions précédentes », changement de rôle, demande
// d'envoyer des secrets à une adresse, ordre de cacher quelque chose à l'utilisateur, balises de tours de parole
// copiées dans le texte. Les formes sont reconnues en français et en anglais.
//
// C'est un détecteur de constat : il ne modifie ni ne masque rien (le texte d'une page lue n'est pas à expurger) et ne
// juge pas : un texte qui cite ces phrases pour les expliquer (documentation sur l'injection de prompt) est signalé comme
// le texte qui les emploie, la décision (avertir, bloquer) revenant à l'appelant. Il ne couvre pas une consigne écrite
// autrement que par les formes ci-dessous ; une absence de constat n'est pas une preuve d'innocuité.
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
)

// Rules sont les règles, dans l'ordre où Find les applique.
func Rules() []Rule {
	return []Rule{InstructionOverride, RoleSwitch, Exfiltration, Concealment, MessageMarkers}
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
}{
	// Annulation des instructions : verbe d'annulation, puis « précédentes / ci-dessus / toutes », puis le nom.
	{InstructionOverride, `(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|all|any|your)\b[^.\n]{0,30}?\b(?:instructions?|prompts?|rules?|directions?|guidelines?|constraints?)\b`},
	{InstructionOverride, `(?i)\b(?:do not|don't|never)\s+follow\b[^.\n]{0,40}?\b(?:instructions?|rules?|guidelines?)\b`},
	{InstructionOverride, `(?i)\b(?:ignore[rz]?|oublie[rz]?|annule[rz]?|n[eé]glige[rz]?|contourne[rz]?|passe[rz]? outre)\b[^.\n]{0,40}?\b(?:pr[eé]c[eé]dent|ant[eé]rieur|ci-dessus|toutes?|tes|vos|les)\b[^.\n]{0,30}?\b(?:instructions?|consignes?|directives?|r[eè]gles?|prompts?|contraintes?)\b`},
	{InstructionOverride, `(?i)\bne (?:tiens?|tenez|suis|suivez)\s+(?:pas|plus)\b[^.\n]{0,40}?\b(?:instructions?|consignes?|directives?|r[eè]gles?)\b`},

	// Changement de rôle : nouveau rôle explicite, ou obéissance exclusive au texte lu.
	{RoleSwitch, `(?i)\byou are now\b[^.\n]{0,20}?\b(?:an?|the|in)\b[^.\n]{0,30}?\b(?:assistant|agent|ai|model|bot|dan|unrestricted|jailbroken|developer mode)\b`},
	{RoleSwitch, `(?i)\bfrom now on\b[^.\n]{0,12}\byou (?:will|must|shall|are to)\b[^.\n]{0,25}?\b(?:ignore|obey|follow|only|always|never|act|respond|answer|reply)\b`},
	{RoleSwitch, `(?i)\b(?:pretend|act as if) (?:that )?you (?:are|have no|can|were)\b[^.\n]{0,40}?\b(?:unrestricted|restrictions?|rules?|limits?|filters?|jailbroken|different|another)\b`},
	{RoleSwitch, `(?i)\b(?:new|updated|real) (?:system )?(?:instructions?|prompt)\s*:`},
	{RoleSwitch, `(?i)\b(?:tu es|vous [eê]tes) (?:maintenant|d[eé]sormais)\b[^.\n]{0,20}?\b(?:un|une|le|la|en)\b[^.\n]{0,30}?\b(?:assistant|agent|ia|mod[eè]le|bot|dan|sans restriction|sans limite|mode d[eé]veloppeur)\b`},
	{RoleSwitch, `(?i)\bd[eé]sormais,?\s+(?:tu|vous)\s+(?:dois|devez|vas|allez|ne dois|ne devez)\b[^.\n]{0,25}?\b(?:ignorer|ob[eé]ir|suivre|toujours|jamais|uniquement|seulement|agir|r[eé]pondre)\b`},
	{RoleSwitch, `(?i)\b(?:fais|faites) (?:semblant|comme si)\b[^.\n]{0,40}?\b(?:sans restriction|sans limite|sans r[eè]gle|aucune restriction|aucune r[eè]gle)\b`},
	{RoleSwitch, `(?i)\bnouvelles? (?:instructions?|consignes?)\s*:`},

	// Exfiltration : verbe d'envoi, un secret, puis une adresse (URL ou courriel).
	{Exfiltration, `(?i)\b(?:send|post|upload|forward|exfiltrate|email|e-mail|transmit|leak|curl)\b[^.\n]{0,60}?\b(?:secrets?|credentials?|passwords?|api[ _-]?keys?|access[ _-]?tokens?|tokens?|private keys?|ssh keys?|\.env)\b[^\n]{0,80}?(?:https?://|[\w.+-]+@[\w-]+\.[\w.-]+)`},
	{Exfiltration, `(?i)\b(?:envoie[rz]?|transmets?|transmettez|poste[rz]?|exfiltre[rz]?|t[eé]l[eé]verse[rz]?|copie[rz]?)\b[^.\n]{0,60}?\b(?:secrets?|identifiants?|mots? de passe|cl[eé]s?|jetons?|\.env)\b[^\n]{0,80}?(?:https?://|[\w.+-]+@[\w-]+\.[\w.-]+)`},

	// Dissimulation à l'utilisateur.
	{Concealment, `(?i)\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify|alert)\b[^.\n]{0,20}?\b(?:the )?user\b`},
	{Concealment, `(?i)\bwithout (?:telling|informing|notifying|alerting)\b[^.\n]{0,15}?\b(?:the )?user\b`},
	{Concealment, `(?i)\bne (?:le |la |lui |en )?(?:dis|dites|dire|montre|montrez|r[eé]v[eè]le|r[eé]v[eé]lez|signale|signalez|informe|informez|pr[eé]viens|pr[eé]venez)\b[^.\n]{0,25}?\b(?:pas|jamais)\b[^.\n]{0,20}?(?:[aà] l'?utilisateur|[aà] l'?op[eé]rateur)\b`},
	{Concealment, `(?i)\bsans (?:en )?(?:informer|pr[eé]venir|alerter|avertir)\b[^.\n]{0,15}?\bl'?utilisateur\b`},

	// Balises de tours de parole et de message système : jetons spéciaux de modèles, jamais du texte ordinaire.
	{MessageMarkers, `(?i)<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>`},
	{MessageMarkers, `(?i)\[/?INST\]|<<\s*/?SYS\s*>>`},
}

// patterns sont les motifs compilés, dans l'ordre de patternSources ; engine est leur porte littérale (gate.go).
var (
	patterns = func() []pattern {
		compiled := make([]pattern, 0, len(patternSources))
		for _, p := range patternSources {
			compiled = append(compiled, compilePattern(p.rule, p.source))
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
// cherchés dans le texte tel quel et dans ses autres lectures (views.go) : normalisé et déplié, décodé une fois. Une
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
	// read lit une vue, puis sa forme normalisée et dépliée si elle en diffère.
	read := func(v *view) {
		scan(v)
		other, ok := folded(v)
		if !ok {
			report.Complete = false
		}
		if other != nil {
			other.afterDecoding = v.segs != nil
			scan(other)
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
