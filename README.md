# SkyGuard

**Quality gate sécurité augmenté par l'IA pour systèmes numériques critiques : SkyGuard simule la surface d'attaque des systèmes numériques d'un avion commercial, puis rejoue à chaque commit un threat modeling STRIDE assisté, un scoring des risques et une traçabilité réglementaire ED-202A.**

[![CI](https://github.com/BazanJeremy/skyguard/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/BazanJeremy/skyguard/actions/workflows/security-pipeline.yml)
[![Tests](https://img.shields.io/badge/tests-252%20passing-brightgreen?logo=pytest)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue?logo=python)](requirements.txt)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

> 🇬🇧 [English version](README.en.md)

## Le problème de validation qualité

Du Playwright sur une *todo app* ne dit rien de la validation d'un système critique. SkyGuard répond à une autre question : **comment valider la qualité et la sécurité d'un système numérique critique, quand une régression peut avoir des conséquences safety ?**

Le projet applique la rigueur QA d'un système régulé à une surface d'attaque avionique **simulée** — la tablette EFB du pilote, le bus de données ARINC 429, la messagerie sol-air ACARS — et en fait un **quality gate** exécuté automatiquement : fuzzing, scénarios d'attaque alignés OWASP, threat modeling STRIDE, et couverture des risques tracée jusqu'aux objectifs réglementaires ED-202A / DO-326A.

---

## L'approche : 3 agents IA + STRIDE

Les trois couches simulées produisent des *findings* de sécurité (contrat commun `SecurityFinding`). Trois agents IA spécialisés les transforment en livrables de qualité. Chacun dispose d'un **fallback déterministe** : la suite de tests et la CI restent vertes **sans aucune clé API**.

```
                       Surface d'attaque simulée
   ┌────────────────┬──────────────────┬─────────────────────┐
   │   ARINC 429    │      ACARS       │       API EFB        │
   │  4 injecteurs  │    6 attaques    │    W1–W5 (Flask)     │
   └───────┬────────┴────────┬─────────┴──────────┬──────────┘
           │                 │                    │
           └────────── findings (SecurityFinding) ───────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
  Pentest Narrator      Threat Modeller       Compliance Mapper
  CVSS · chaînes        STRIDE (6 cat.)       ED-202A / DO-326A
  d'attaque · plan      · arbres d'attaque    · matrice d'écarts
  de remédiation        · tests suggérés      · actions correctives
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
   pentest-report.md · stride-threat-model.md · compliance-matrix.md
              (+ issue GitHub automatique · rapport Allure)

  Chaque agent : Claude si ANTHROPIC_API_KEY, sinon fallback déterministe.
  Coordination via demo.py — contrat commun, pas d'orchestration réseau.
```

- **Pentest Narrator** — `list[SecurityFinding]` → scores CVSS v3.1 (avec vecteurs), chaînes d'attaque multi-étapes, plan de remédiation priorisé, mapping ED-202A.
- **Threat Modeller** — une *User Story* au format Gherkin → modèle STRIDE (les 6 catégories), arbres d'attaque, noms de tests suggérés en convention pytest.
- **Compliance Mapper** — `list[SecurityFinding]` → matrice ED-202A (SO-1…SO-6) / DO-326A, notation des écarts (🔴 critique → 🟢 conforme), actions correctives.

---

## Un scénario concret, de bout en bout

**Question qualité :** *un pilote peut-il lire le plan de vol d'un autre pilote ?*

1. **Test** — `test_pilot_cannot_access_other_pilots_plan` envoie `GET /api/v1/flightplans/fp002` avec le jeton du commandant Dubois (propriétaire de `fp001` seulement). L'API répond `200 OK` : accès indirect non contrôlé confirmé (faiblesse **W3 — IDOR**).
2. **Pentest Narrator** — score **CVSS 8.1 (élevé)** et identifie une chaîne d'attaque : *endpoint `/debug` non authentifié (W4) → énumération des jetons actifs → IDOR (W3) → lecture de n'importe quel plan de vol*.
3. **Compliance Mapper** — mappe sur **ED-202A SO-3** (« Implement security controls »), écart **majeur**, action corrective précise : contrôle de propriété `plan.owner_id == current_user.id` sur les routes GET / PUT / DELETE.

**Livrables produits** dans `reports/` : `pentest-report.md`, `stride-threat-model.md`, `compliance-matrix.md`.
Le correctif se démontre en une variable d'environnement : `FLASK_ENV=production` fait disparaître l'endpoint `/debug` (W4).

---

## Lancer la démo en local

```bash
git clone https://github.com/BazanJeremy/skyguard.git && cd skyguard
pip install -r requirements.txt

# Pipeline IA complet — mode fallback, aucune clé requise
python demo.py --save

# Suite complète — 252 tests, ~8 s
python -m pytest
```

Avec une clé API (analyse IA « live ») :
```bash
ANTHROPIC_API_KEY=sk-ant-... python demo.py --save
```

Démonstration du correctif W4 :
```bash
FLASK_ENV=production python demo.py   # l'endpoint /debug renvoie 403
```

Environnement complet (API EFB conteneurisée) :
```bash
cp .env.example .env
docker compose up            # API EFB → http://localhost:5050
```

---

## Surface d'attaque simulée

| Couche | Fichier | Ce qui est testé |
|---|---|---|
| **ARINC 429** | `src/simulators/arinc429_bus.py` | Bus avionique 32 bits (label / SDI / data / SSM / parité). 4 injecteurs : hors-plage, corruption de parité, spoofing SSM, rejeu de trames. |
| **ACARS** | `src/simulators/acars_parser.py` | Parser de messagerie sol-air (ARINC 618). 6 attaques : overflow, injection de *null bytes*, adresse malformée, ETX manquant, injection de label, rejeu de clairance ATC. |
| **API EFB** | `src/simulators/efb_api/efb_app.py` | API REST Flask (13 routes). 5 faiblesses intentionnelles et documentées, W1–W5. |

**Les 5 faiblesses de l'API EFB :**

| ID | Faiblesse | OWASP | CVSS v3.1 | Enjeu ED-202A |
|---|---|---|---|---|
| W1 | Pas de rate-limit sur `/auth/token` | A07 | 7.5 | SO-3 : brute-force d'identité pilote |
| W2 | Secret JWT en dur, exposé via `/debug` | A02 | **9.8** | SO-3 : forge de jetons |
| W3 | IDOR sur `/flightplans/<id>` | A01 | 8.1 | SO-3 : accès croisé aux plans de vol |
| W4 | Endpoint `/debug` non authentifié | A05 | **9.1** | SO-3 : jetons + secret exposés |
| W5 | Traces d'exécution dans les réponses | A09 | 5.3 | SO-6 : facilite l'exploitation |

**Couverture des tests** — 252 passés, 6 ignorés (~8 s, sans clé API) :

| Couche | Tests |
|---|---|
| Protocole (ARINC 429 + ACARS) | 82 |
| Fuzzing (Hypothesis, 50 000+ cas par run) | 27 |
| Sécurité (API EFB, W1–W5) | 71 |
| Agents IA (contrats, fallback, rendu) | 72 |

---

## Stack technique

| Rôle | Outil |
|---|---|
| Langage | Python 3.11 / 3.12 |
| Simulateur d'API | Flask 3.x |
| Tests | Pytest 9.x + Hypothesis |
| Agents IA | Claude (sortie JSON structurée, prompts versionnés) |
| SAST | Bandit + Semgrep → SARIF (onglet GitHub Security) |
| Reporting | Allure → GitHub Pages |
| CI/CD | GitHub Actions (matrice 3.11 / 3.12) |
| Conteneurs | Docker Compose |

Tous les outils sont **libres et open-source**.

---

## Limites explicites

> **SkyGuard est une simulation académique, PAS un outil de sécurité de production.** C'est une **méthode** QA × sécurité appliquée de bout en bout, pas un produit de pentest.

- Aucune donnée d'avion réelle, aucun système avionique certifié, aucun environnement de production n'est impliqué.
- Le mapping ED-202A / DO-326A est **illustratif, pas certifiant** : une vraie certification exige l'engagement d'un organisme agréé EASA (voir [ADR-003](docs/ADR-003-compliance-scope.md)).
- Les faiblesses W1–W5 et les attaques protocolaires sont **volontaires** : elles servent de cible de test documentée, pas d'exemples de code à réutiliser.
- RabbitMQ (dans `docker-compose.yml`) est une infra de démonstration ; il n'est pas câblé au pipeline d'agents, qui s'exécute en mémoire via `demo.py`.

---

## Décisions d'architecture

| ADR | Décision | Pourquoi c'est important |
|---|---|---|
| [ADR-001](docs/ADR-001-protocol-simulation.md) | Simulation protocolaire en Python pur | Indépendant du matériel, compatible CI, testable par Hypothesis |
| [ADR-002](docs/ADR-002-ai-agent-design.md) | Claude + fallback déterministe | La CI n'est jamais bloquée par une clé manquante |
| [ADR-003](docs/ADR-003-compliance-scope.md) | Compliance mapper illustratif, pas certifiant | Cadrage honnête = signal de maturité sur le domaine régulé |

---

## Projets associés

Ces outils partagent les mêmes principes : **le déterministe d'abord, l'IA là où elle apporte — le QA reste l'arbitre.** Tous tournent en local, aucune clé API requise.

| Projet | Focus |
|---|---|
| [EvalForge](https://github.com/BazanJeremy/EvalForge) | Évaluation de LLM & calibration du juge |
| [ReleaseGuard](https://github.com/BazanJeremy/ReleaseGuard) | Verrou de release GO/NO-GO explicable |
| [FlakySense](https://github.com/BazanJeremy/flakysense) | Diagnostic statistique des tests flaky |
| [Anomaly Sentinel](https://github.com/BazanJeremy/anomaly-sentinel) | Tester les IA de détection d'anomalies (medtech · fintech) |
| [TestScribe](https://github.com/BazanJeremy/testscribe) | Enrichissement de bug reports assisté par IA |
| [SkyGuard](https://github.com/BazanJeremy/skyguard) **← ce repo** | Quality gate sécurité pour systèmes critiques avioniques |

## Auteur

**Jérémy Bazan** — Ingénieur QA / Lead Tech QA, référent IA de pôle.
Validation de systèmes critiques, automatisation de test, quality gates orientés IA.

🔗 [linkedin.com/in/jeremy-bazan](https://www.linkedin.com/in/jeremy-bazan/)

---

*SkyGuard — Licence [MIT](LICENSE).*
