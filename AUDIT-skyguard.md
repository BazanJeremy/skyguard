# Prompt d'audit — SkyGuard (P2)

> À coller dans Claude Code, à la racine du repo, après un `/clear`.
> CLAUDE.md doit déjà être présent à la racine (il sera lu automatiquement).

---

Le projet est en statut COMPLETE (252/252 tests, 3 agents IA, Docker, Allure, CI/CD). Je ne veux AUCUNE réécriture, refactor ou "amélioration" sans validation explicite. Ta mission est un AUDIT en lecture, pas une intervention.

Objectif : vérifier qu'on n'est passé à côté de rien, en particulier sur les parties les plus fragiles (Docker, Allure, les 3 agents). Rapport structuré (✅ solide / ⚠️ à surveiller / 🔧 correctif proposé — jamais appliqué sans mon accord).

## 1. Suite de tests
- Lance `python -m pytest -v`, confirme 252/252 verts, relève le temps d'exécution.
- Relance une deuxième fois pour détecter une flakiness éventuelle.

## 2. Fallback déterministe (3 agents)
- Pour chacun des 3 agents IA, confirme l'existence d'un fallback rule-based et que la suite passe sans clé API définie.
- Signale si un agent dépend implicitement d'un autre d'une manière qui casserait le fallback en cascade.

## 3. Docker
- Vérifie que `docker build` (ou `docker-compose build`) fonctionne toujours sans erreur.
- Signale toute image de base dépréciée ou tag `latest` non pinné qui pourrait casser la reproductibilité.

## 4. Allure
- Vérifie que la génération du rapport Allure fonctionne (`allure generate` ou équivalent) sans planter.
- Ne lis PAS le contenu de `allure-results/` ou `allure-report/` en détail (token waste) — juste confirme que la commande s'exécute proprement.

## 5. Dépendances & sécurité
- `pip list --outdated`.
- Vérifie qu'aucune assertion de sécurité (STRIDE / CVSS / OWASP / EASA) n'a été affaiblie ou contournée pour "faire passer" un test.

## 6. Secrets et hygiène repo
- Grep pour clés API, tokens, credentials committés par erreur.
- Vérifie `.gitignore` (`.venv/`, caches, `allure-results/`, `allure-report/`, caches Docker).

## 7. Cohérence documentaire
- Compare le README (nombre de tests, description des 3 agents, instructions Docker) avec l'état réel.
- Vérifie que les ADRs correspondent toujours à l'implémentation (notamment les choix STRIDE/CVSS/EASA).

## 8. Qualité résiduelle
- `TODO`/`FIXME`, code mort, commentaires obsolètes.

## Livrable attendu

Rapport unique en anglais professionnel, ✅/⚠️/🔧 par section. Propose sans appliquer. Si tout est vert, confirme-le simplement.
