// Exécution des familles de règles d'une vue, en parallèle quand elles ne consomment aucun budget partagé.
//
// Les familles sans budget (clés privées, règles « motif seul » sans validateur, URL à identifiants, motifs
// d'affectation, cookies, « -u utilisateur:mot de passe », entropie) ne lisent que la vue et les règles, immuables
// pendant l'analyse : chacune écrit ses constats dans sa case. Les familles qui débitent le budget de décodage (règles
// à validateur, dont jwt, et clé auth de Docker) s'exécutent dans le fil de l'appelant, dans leur ordre d'origine :
// l'issue « incomplète » dépend de l'ordre des débits. Les constats sont ensuite concaténés dans l'ordre exact de
// l'analyse séquentielle (sequentialDetectors), dont dépend la déduplication à clés égales : même résultat, octet
// pour octet, quel que soit le nombre de fils.

package detect

import (
	"errors"
	"sync"
)

const (
	// defaultWorkers : fils d'une vue quand Options.Workers vaut 0 (borné par le nombre de familles sans budget).
	defaultWorkers = 8
	// defaultParallelMinViewBytes : en deçà, une vue est analysée par sequentialDetectors (lancer des fils coûterait
	// plus que le travail gagné).
	defaultParallelMinViewBytes = 1 << 10
)

// parallelMinViewBytes est la taille, en octets, de la plus petite vue analysée en parallèle ; couture de test (les
// tests la mettent à 0 pour exécuter le chemin parallèle sur toute entrée).
var parallelMinViewBytes = defaultParallelMinViewBytes

// errDetectorPanic : une famille exécutée par un fil a paniqué ; l'analyse est incomplète (FailureScanError), comme
// pour une panique dans le fil de l'appelant.
var errDetectorPanic = errors.New("détection : panique dans une famille de règles")

// detectorTask est l'exécution d'une famille sur une vue. budgeted : elle débite le budget de décodage. rank : ordre
// de départ des familles sans budget (les plus longues d'abord, rang 0), sans effet sur l'ordre des constats.
type detectorTask struct {
	run      func() ([]finding, error)
	budgeted bool
	rank     int
}

// Rangs de départ : motifs d'affectation (le premier, ASSIGNMENT, est le plus long), puis les autres familles qui
// parcourent tout le texte par une expression, puis celles qu'une porte littérale arrête le plus souvent.
const (
	rankAssignment = iota
	rankFullText
	rankGated
	ranks
)

// detectors suit scanDetectors de Secret Guard : séquentiel (sequentialDetectors) ou parallèle, même résultat.
func (s *scanState) detectors(v *view, entropy bool, lang language, allowStructured bool) ([]finding, error) {
	if s.workers == 1 || s.workers < 0 || len(v.text) < parallelMinViewBytes {
		return s.sequentialDetectors(v, entropy, lang, allowStructured)
	}
	return s.parallelDetectors(v, entropy, lang, allowStructured)
}

// parallelDetectors exécute les familles de detectorTasks : celles qui débitent le budget dans le fil de l'appelant,
// dans l'ordre, puis l'appelant aide les fils ; les autres par au plus workers fils en tout. Budget épuisé après les
// familles à budget (déjà ou par elles) : errDecodeBudgetExhausted, comme sequentialDetectors. La première erreur
// dans l'ordre des familles l'emporte ; une panique d'un fil est rattrapée (errDetectorPanic), et l'appelant attend
// toujours la fin de tous les fils avant de rendre (même s'il panique), car les tampons des vues sont effacés ensuite.
func (s *scanState) parallelDetectors(v *view, entropy bool, lang language, allowStructured bool) ([]finding, error) {
	tasks := detectorTasksOf(s.rules, v, s.decode, entropy, lang, allowStructured)
	results := make([][]finding, len(tasks))
	errs := make([]error, len(tasks))
	queue := make(chan int, len(tasks))
	free := 0
	for rank := range ranks {
		for i, task := range tasks {
			if !task.budgeted && task.rank == rank {
				queue <- i
				free++
			}
		}
	}
	close(queue)
	work := func() {
		for i := range queue {
			results[i], errs[i] = recovered(tasks[i].run)
		}
	}
	workers := s.workers
	if workers == 0 {
		workers = defaultWorkers
	}
	workers = min(workers, free)
	var wg sync.WaitGroup
	for range workers - 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			work()
		}()
	}
	func() {
		defer wg.Wait()
		for i, task := range tasks {
			if !task.budgeted {
				continue
			}
			// Comme sequentialDetectors : une erreur ou un budget épuisé arrête les familles à budget suivantes.
			if results[i], errs[i] = task.run(); errs[i] != nil || s.decode.exhausted {
				break
			}
		}
		work()
	}()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	if s.decode.exhausted {
		return nil, errDecodeBudgetExhausted
	}
	total := 0
	for _, found := range results {
		total += len(found)
	}
	out := make([]finding, 0, total)
	for _, found := range results {
		out = append(out, found...)
	}
	return out, nil
}

// recovered exécute une famille dans un fil : une famille qui ne finit pas normalement (panique, même panic(nil) sous
// GODEBUG=panicnil=1 où recover rend nil, ou runtime.Goexit) rend errDetectorPanic ; la panique n'est jamais propagée
// hors du fil, ce qui arrêterait le processus.
func recovered(run func() ([]finding, error)) (found []finding, err error) {
	done := false
	defer func() {
		_ = recover()
		if !done {
			found, err = nil, errDetectorPanic
		}
	}()
	found, err = run()
	done = true
	return found, err
}

// detectorTasksOf rend les familles d'une vue (Rules.detectorTasks) ; couture de test (familles fautives injectées).
var detectorTasksOf = (*Rules).detectorTasks

// detectorTasks rend les familles d'une vue dans l'ordre de concaténation de sequentialDetectors : clés privées,
// règles « motif seul » dans l'ordre du Pack, URL à identifiants, motifs d'affectation, cookies, « -u », clé auth de
// Docker, entropie. Chaque motif d'affectation et la clé auth de Docker ont leur propre contextualText : ses tables
// sont des mémos d'un calcul sur le texte de la vue, sans effet sur les résultats.
func (r *Rules) detectorTasks(v *view, budget *decodeBudget, entropy bool, lang language, allowStructured bool) []detectorTask {
	tasks := []detectorTask{{run: func() ([]finding, error) { return r.scanPrivateKeys(v), nil }, rank: rankGated}}
	for _, fixed := range r.fixed {
		if fixed.validator != nil && !allowStructured {
			continue
		}
		scanRule := scanFixedPattern
		if fixed.id == ruleJWT {
			scanRule = scanJWT
		}
		tasks = append(tasks, detectorTask{
			run:      func() ([]finding, error) { return scanRule(v, fixed, budget, nil) },
			budgeted: fixed.validator != nil,
			rank:     rankGated,
		})
	}
	tasks = append(tasks, detectorTask{run: func() ([]finding, error) { return r.scanCredentialURLs(v), nil }, rank: rankFullText})
	if r.hasContextualTypes() {
		for i := range assignmentPatterns {
			p := &assignmentPatterns[i]
			tasks = append(tasks, detectorTask{run: func() ([]finding, error) {
				return r.scanAssignmentPattern(v, newContextualText(v.text), p, lang, nil), nil
			}, rank: rankAssignment})
		}
	}
	tasks = append(tasks,
		detectorTask{run: func() ([]finding, error) { return r.scanCookieCredentials(v, nil), nil }, rank: rankFullText},
		detectorTask{run: func() ([]finding, error) { return r.scanBasicAuthArguments(v, nil), nil }, rank: rankFullText},
	)
	if allowStructured {
		tasks = append(tasks, detectorTask{
			run:      func() ([]finding, error) { return r.scanDockerAuth(v, newContextualText(v.text), budget, nil) },
			budgeted: true,
		})
	}
	if entropy {
		tasks = append(tasks, detectorTask{run: func() ([]finding, error) { return r.scanEntropy(v), nil }, rank: rankFullText})
	}
	return tasks
}
