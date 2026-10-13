/**
 * `npm run pack:initial` (dans `generator/`) : écrit `pack/initial/pack.json` et les motifs du moteur Go
 * (`detect/engine_patterns.go`) depuis la copie figée du catalogue Secret Guard (`pack/initial/upstream/rules.ts.txt`).
 * Déterministe ; les tests `le Pack initial reprend chaque règle du catalogue Secret Guard` et `les motifs du moteur Go
 * sont ceux du générateur` exigent l'égalité. Ne signe rien : la signature d'un Pack, s'il en faut une, est l'affaire
 * de celui qui le distribue.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { RulePack } from '../src/rule-pack.ts';
import { buildInitialPack, serializePack } from './catalog.ts';
import { buildEnginePatternsGo } from './engine-patterns.ts';

const upstream = new URL('../../pack/initial/upstream/rules.ts.txt', import.meta.url);
const target = new URL('../../pack/initial/pack.json', import.meta.url);
const engineTarget = new URL('../../detect/engine_patterns.go', import.meta.url);

const upstreamText = readFileSync(upstream, 'utf8');
const pack = RulePack.parse(buildInitialPack(upstreamText));
const engine = buildEnginePatternsGo(upstreamText);
writeFileSync(target, serializePack(pack));
writeFileSync(engineTarget, engine);
process.stdout.write(`Pack initial écrit : ${String(pack.rules.length)} règles ; motifs du moteur Go écrits\n`);
