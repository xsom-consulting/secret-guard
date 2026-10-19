package detect

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Bancs publics de l'analyse (docs/bench.md) : texte déterministe fait de code et de prose, sans secret (« propre »)
// ou avec des secrets synthétiques construits en morceaux à l'exécution (« secrets »), aux tailles de 2, 16, 64 et
// 256 Kio. Commande : go test -run XXX -bench 'BenchmarkScan/' -benchtime 20x ./detect

// benchSizes : tailles des bancs, en Kio.
var benchSizes = []int{2, 16, 64, 256}

// benchLines : lignes de code et de prose, en français et en anglais, sans secret.
var benchLines = []string{
	`import { readFile } from "node:fs/promises";`,
	`export async function load(path: string): Promise<Config> {`,
	`  const text = await readFile(path, "utf8"); // lecture du fichier de configuration`,
	`  return JSON.parse(text) as Config;`,
	`}`,
	`const url = "https://api.example.com/v1/items?limit=50&offset=100";`,
	`func (s *Server) handle(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }`,
	`    for (let i = 0; i < items.length; i++) { total += items[i].price * items[i].quantity; }`,
	`def summarize(rows):`,
	`    return {"count": len(rows), "total": sum(row["amount"] for row in rows)}`,
	`SELECT id, name, created_at FROM customers WHERE region = 'eu-west' ORDER BY created_at DESC;`,
	`2026-10-19T08:15:42.123Z INFO request completed method=GET status=200 duration=12ms`,
	`DATABASE_HOST=db.internal`,
	`{"name": "demo", "version": "1.2.3", "dependencies": {"zod": "^4.0.0"}}`,
	`Peux-tu relire cette fonction et me dire pourquoi le test échoue quand la liste est vide ?`,
	`The cache is invalidated when the configuration changes, so the next request reloads it from disk.`,
	`Le Développeur ajoute une colonne à la table, puis il écrit la migration et le test qui la vérifie.`,
	`Please keep the public API unchanged and add a short note to the changelog for the next release.`,
	`// TODO: gérer le cas où le fichier n'existe pas encore (première exécution).`,
	`  if err != nil { return fmt.Errorf("lecture de %s : %w", path, err) }`,
}

// benchSecrets : secrets synthétiques, construits en morceaux (aucun n'est écrit en clair dans le dépôt).
func benchSecrets() []string {
	password := "pass" + "word"
	return []string{
		"token := \"" + "gh" + "p_" + strings.Repeat("aB3d", 9) + "\"",
		password + " = \"hunter2-" + entropyValue(12) + "\"",
		"AWS_ACCESS_KEY_ID=" + "AK" + "IA" + "Q7K2M9X4B6N8P3R5",
		"auth: " + b64(password+"="+entropyValue(16)),
		"postgres://admin:" + "s3cr3t" + "-" + entropyValue(10) + "@db.example.com:5432/app",
	}
}

// benchText rend un texte déterministe de size octets exactement. Avec secrets, un secret synthétique est inséré tous
// les 8 Kio (au moins un), toujours en début de ligne.
func benchText(size int, secrets bool) []byte {
	var b strings.Builder
	list := benchSecrets()
	nextSecret, secretIndex := 0, 0
	for line := 0; b.Len() < size; line++ {
		if secrets && b.Len() >= nextSecret {
			b.WriteString(list[secretIndex%len(list)])
			b.WriteByte('\n')
			secretIndex++
			nextSecret += 8 << 10
		}
		b.WriteString(benchLines[line%len(benchLines)])
		b.WriteString(" // ")
		b.WriteString(strconv.Itoa(line))
		b.WriteByte('\n')
	}
	text := []byte(b.String())[:size]
	// Fin de ligne : la coupe ne laisse jamais un secret tronqué au bout du texte.
	for i := len(text) - 1; i >= 0 && text[i] != '\n'; i-- {
		text[i] = ' '
	}
	return text
}

func BenchmarkScan(b *testing.B) {
	rules := loadInitialRules(b)
	for _, kib := range benchSizes {
		for _, variant := range []struct {
			name    string
			secrets bool
		}{{"propre", false}, {"secrets", true}} {
			content := benchText(kib<<10, variant.secrets)
			b.Run(fmt.Sprintf("%dKiB/%s", kib, variant.name), func(b *testing.B) {
				result := Scan(content, rules, Options{})
				if !result.Complete || (len(result.Findings) == 0) == variant.secrets {
					b.Fatalf("issue %s, %d constats", result.Failure, len(result.Findings))
				}
				b.SetBytes(int64(len(content)))
				b.ResetTimer()
				for b.Loop() {
					Scan(content, rules, Options{})
				}
			})
		}
	}
}

// BenchmarkScanSequential mesure la porte littérale seule (Options.Workers à 1 : un seul fil), à 64 Kio.
func BenchmarkScanSequential(b *testing.B) {
	rules := loadInitialRules(b)
	for _, secrets := range []bool{false, true} {
		name := "propre"
		if secrets {
			name = "secrets"
		}
		content := benchText(64<<10, secrets)
		b.Run("64KiB/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(content)))
			for b.Loop() {
				Scan(content, rules, Options{Workers: 1})
			}
		})
	}
}
