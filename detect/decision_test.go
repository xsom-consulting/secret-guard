package detect

import "testing"

// Vecteurs des niveaux et décisions, produits par le moteur TypeScript de Secret Guard avec ceux du masquage
// (generator/redact/, npm run vectors:redact -- --upstream <checkout>).
const decisionVectorsFile = "../vectors/decision.json"

// TestDecisionParity : levelForScore, boundedScore et decisionForLevel du moteur d'origine (vectors/decision.json)
// sont exactement ceux du moteur Go, sur chaque score entier de -5 à 105 et chaque niveau ; un niveau hors de la liste
// fermée bloque (écart volontaire : non représentable dans les types de l'origine).
func TestDecisionParity(t *testing.T) {
	t.Run("niveaux, scores bornés et décisions identiques à Secret Guard", func(t *testing.T) {
		var vectors struct {
			FormatVersion  int    `json:"formatVersion"`
			UpstreamCommit string `json:"upstreamCommit"`
			Scores         []struct {
				Score   int    `json:"score"`
				Bounded int    `json:"bounded"`
				Level   string `json:"level"`
			} `json:"scores"`
			Levels []struct {
				Level    string `json:"level"`
				Decision string `json:"decision"`
			} `json:"levels"`
		}
		readStrict(t, decisionVectorsFile, &vectors)
		if vectors.FormatVersion != 1 || len(vectors.Scores) != 111 || len(vectors.Levels) != 4 {
			t.Fatalf("vecteurs des décisions de format inconnu")
		}
		for _, s := range vectors.Scores {
			if got := boundedScore(s.Score); got != s.Bounded {
				t.Errorf("boundedScore(%d) = %d, attendu %d", s.Score, got, s.Bounded)
			}
			if got := levelForScore(s.Score); string(got) != s.Level {
				t.Errorf("levelForScore(%d) = %s, attendu %s", s.Score, got, s.Level)
			}
		}
		levels := map[Level]bool{}
		for _, l := range vectors.Levels {
			levels[Level(l.Level)] = true
			if got := DecisionForLevel(Level(l.Level)); string(got) != l.Decision {
				t.Errorf("DecisionForLevel(%s) = %s, attendu %s", l.Level, got, l.Decision)
			}
		}
		for _, level := range []Level{LevelLow, LevelMedium, LevelHigh, LevelCritical} {
			if !levels[level] {
				t.Errorf("niveau absent des vecteurs : %s", level)
			}
		}
		for _, level := range []Level{"", "low", "UNKNOWN"} {
			if got := DecisionForLevel(level); got != DecisionBlock {
				t.Errorf("niveau hors liste %q : %s", level, got)
			}
		}
	})
}
