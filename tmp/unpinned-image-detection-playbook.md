# Playbook: Detecting Unpinned Container Images Across an Organization's Repos

A reusable methodology for finding every mutable (unpinned) container-image
reference in a codebase — from a single repo up to a whole GitHub
organization — developed during the 2026 Shai-Hulud supply-chain incident
response at GenericSuite and otheer OSS projects. Everything here is
grep/parser-level static analysis — no cluster access, no image pulls, no
chart rendering — and each strategy is annotated with what it actually
caught and the mistakes we made, because the mistakes are the transferable
part.

## 1. Why unpinned images matter

A container image reference is **mutable** unless it includes a digest
(`image@sha256:…`). Anyone who can push to the tag — via a stolen registry
token, a compromised maintainer account, or an abandoned namespace —
silently changes what your CI runs and what production deploys, with no
commit in your repos. During a worm-style attack (Shai-Hulud steals npm and
Docker Hub tokens), every `:latest` your pipelines pull is an open door.

The risk is not uniform. Classify every finding on two axes:

- **How mutable** — see the classification table (§3).
- **Where it executes** — a `:latest` running in CI *with credentials* or in
  production desired state matters far more than one in a hackathon's
  docker-compose.

## 2. Choose a corpus (the strategies don't care which)

Every strategy in this playbook is a *search over files*. It works the same
whether the corpus is one repo, a monorepo, a CI checkout, or every repo in
an organization — pick the corpus that matches your question:

| Corpus | Good for | Caveats |
|---|---|---|
| **A single repo checkout** | Per-repo audit, PR review, a pre-commit/CI lint step | Misses org-wide patterns (shared CI images used everywhere) |
| **CI job per repo** | Continuous enforcement — run the passes as a lint on every push | Each repo only sees itself; aggregate results centrally |
| **Hosted code search** (GitHub search, Sourcegraph, `gh search code`) | Fast lower bound, zero setup, quick probes | GitHub caps at ~1000 results, skips forks/unindexed files, no regex over all file types — never treat as complete |
| **All repos cloned locally** | Incident response, one-shot exhaustive inventory | See operational notes below |

For org-wide *incident response* we recommend local clones — a whole org is
usually a few GiB shallow-cloned, and it's the only corpus on which "we
searched everything" is a true statement:

```bash
gh repo list <ORG> --no-archived --limit 1000 \
  --json name,defaultBranchRef,isFork,isEmpty > repos.json

# Per repo (parallelize with xargs -P8):
GIT_LFS_SKIP_SMUDGE=1 git \
  -c core.hooksPath=/dev/null \
  -c filter.lfs.smudge=cat -c filter.lfs.process= -c filter.lfs.required=false \
  -c credential.helper= -c 'credential.helper=!gh auth git-credential' \
  clone --quiet --depth 1 --single-branch --no-tags \
  "https://github.com/<ORG>/$name.git" "repos/$name"
```

Operational notes for the local-clone corpus, learned the hard way:

- **Treat cloned repos as hostile input**: disable hooks, LFS smudge, and
  checkout filters (flags above). Never execute anything from the clones.
- **Credential helpers**: parallel HTTPS clones on macOS trigger one
  Keychain prompt *per git process*. The inline
  `credential.helper=!gh auth git-credential` override uses the `gh` token
  directly and prompts zero times, without touching global git config.
- Clone into a temp dir and rename on success, so an interrupted clone is
  never mistaken for a completed one. Record HEAD SHA per repo so the scan
  is attributable to an exact snapshot.

Whatever the corpus, exclude vendored/generated paths from every search:
`node_modules/`, `vendor/`, `dist/`, `build/`, `.git/`. The example
commands below use `grep -rn` over a directory of clones — translate them
mechanically to your corpus (`rg` flags, code-search queries, a CI script);
it's the *patterns and the file types* that transfer, not the tool.

## 3. What counts as unpinned

| Reference | Class | Mutable? |
|---|---|---|
| `img@sha256:…` (with or without tag) | digest | No — pinned |
| `img:1.27.4` | version tag | Yes, but low risk (registry owner can re-push; use digest for zero trust) |
| `img:14`, `img:pg16` | major-only | Yes — tracks releases |
| `img:bullseye-slim`, `ubuntu:trusty` | codename | Yes — patch-mutable, but names a fixed release; treat like a version tag |
| `img:stable`, `img:main`, `img:dev`, `img:nightly` | floating alias | **Yes — high risk** |
| `img:alpine`, `img:slim` (variant only, no version) | versionless variant | **Yes — this IS latest** on that track |
| `img:latest` | latest | **Yes — highest risk** |
| `img` (no tag at all) | untagged | **Identical to `:latest`** — Docker resolves it that way |

Decide your boundary explicitly (we drew it at "codename and version tags
are acceptable; anything with no version component is not") and state it in
the report, so reviewers argue with the policy instead of the data.

Also decide the **ownership boundary**: images in registries your org
controls may be excluded from remediation — but note that org images on
*public Docker Hub* are only as safe as that account's credentials, which
is exactly what these worms steal.

## 4. Detection passes — by name/key (fast, cover 80%)

Each pass is defined by **what pattern to look for and in which file
types**; the `grep` invocations are just one encoding of that. Run them
over whatever corpus you chose in §2.

### 4.1 Explicit `:latest` in YAML

```bash
grep -rn --include='*.yml' --include='*.yaml' ':latest' . \
  | grep -vE '/(node_modules|vendor|\.git|dist|build)/'
```

Catches compose files, Helm values, k8s manifests, GitHub Actions
`container:`/`services:` images, Bitbucket/GitLab CI. Expect a few false
positives (comments, echo strings) — skim, don't script them away.

### 4.2 Untagged images under image-ish YAML keys

```bash
grep -rnE --include='*.yml' --include='*.yaml' \
  '^[[:space:]-]*(image|containerImage|imageReference|reference):[[:space:]]*["'"'"']?[A-Za-z0-9][A-Za-z0-9./_-]*["'"'"']?[[:space:]]*(#.*)?$' .
```

The value having **no colon** means no tag. Expect noise: this collides
with dbt `reference:` columns, asset paths (`image: logo.png`), Ansible
AMI ids (`image: ami-…`), and non-image config. Filter by eye or by path.
Extend the key list per ecosystem — we later found `postgresImage:`,
`lbCronImage:`, `imageReference:` in the wild; a `/image/i` key-substring
match via a YAML parser is the robust version.

**GitLab CI trap**: services are declared as `- name: <image>`, not
`image:`. Sweep `.gitlab-ci*.yml` separately for that form. (Found an
untagged CI service this way that every `image:` grep missed.)

### 4.3 Dockerfiles — parse, don't grep

Discover by name (`Dockerfile*`, `*.dockerfile`, `Containerfile*`) **and**
scan `FROM` lines. But naive grep filters fail here; we shipped two bugs:

- Filtering out `FROM <one-word>` to skip stage refs (`FROM builder`) also
  deletes genuine untagged images (`FROM node`).
- Filtering out lines containing ` AS ` to skip stage definitions deletes
  real findings like `FROM whitfin/geoipupdate AS geoip` — which turned out
  to be an untagged personal-account image in a production image build.

The only reliable approach is a tiny parser that: joins backslash
continuations, collects `ARG name=default` and substitutes `$VAR`/`${VAR}`
in FROM lines, records stage aliases (`FROM x AS name`) and skips later
references to them, strips `--platform`, skips `scratch`, then classifies
the remaining refs by the §3 table. ~60 lines of Python. Also check
`COPY --from=<image>` and `RUN --mount=from=<image>` for non-stage sources.

### 4.4 Floating alias tags

```bash
grep -rnE --include='*.yml' --include='*.yaml' \
  ':(latest|stable|main|master|edge|nightly|dev|develop|staging|prod|production)["'"'"']?[[:space:]]*$' .
```

### 4.5 Versionless variant tags (latest in disguise)

Tags containing **no digits** (`:alpine`, `:slim`, `:stable-alpine…`) pin
nothing. Sweep YAML values and parser output for digitless tags; then
manually separate codenames (`wheezy`, `trusty`, `bullseye-slim` — treat
as version-class) from true variants. This caught `redis:alpine` and
`nginx:alpine` that every other pass classified as "tagged, fine".

## 5. Detection passes — name-independent (find what you can't name)

These find images with no key, no known name, and no YAML at all. In our
run they produced the single most serious finding of the whole exercise.

### 5.1 Inline `docker pull|run|create` in scripts and CI run-blocks

```bash
grep -rnE --include='*.sh' --include='Makefile*' --include='package.json' \
  'docker +(pull|run|create)' .
# and separately inside workflow YAML (run: blocks execute arbitrary shell):
grep -rnE --include='*.yml' --include='*.yaml' 'docker +(pull|run)' . \
  | grep '/.github/workflows/'
```

CI job containers get audited; a `docker pull` inside a `run:` step does
not. This found an untagged personal-account image pulled and executed
**in CI with secrets in its environment**, and dev scripts mounting
`~/.aws` into `:latest` containers. Beware multi-line `docker run \`
commands: grep the *files*, then read the full command, or you'll only see
the flags and miss the image on a continuation line.

### 5.2 Registry-hostname sweep (all file types)

Search for *where images live* instead of what they're called:

```bash
grep -rnEoh \
  '(ghcr\.io|quay\.io|gcr\.io|registry\.k8s\.io|mcr\.microsoft\.com|docker\.elastic\.co|public\.ecr\.aws|registry\.gitlab\.com|docker\.io|[a-z0-9-]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com)/[a-z0-9._/-]+(:[a-zA-Z0-9._-]+)?' . \
  | sort | uniq -c | sort -rn
```

Runs over every file type — JSON, HCL, Starlark, shell, lock files. Even
when it finds nothing new, it's your best *validation* pass: a deduped
inventory of every registry-qualified ref and its tag, at a glance.

### 5.3 Structured config that lists images

- **JSON image lists**: runner/VM "toolset" files, devcontainer.json,
  ECS task definitions. Found `moby/buildkit:latest` baked into
  self-hosted CI runner images via a `toolset-*.json`.
- **Helm mapping form**: `repository:` + `tag:` as separate keys — the
  dominant Helm pattern, invisible to every single-line grep. Grep
  `repository:` values in `values*.yaml` that aren't chart-repo URLs, then
  check whether an adjacent `tag:`/`digest:` exists. A **missing** `tag:`
  here means the upstream chart's default decides what deploys. Found an
  identity provider (`bitnamilegacy/keycloak`) running with no tag in
  values, from an unmaintained namespace.
- **Kustomize**: `images:` overrides and remote bases
  (`github.com/...?ref=`) in `kustomization.yaml`.
- **Terraform**: `image` attributes in ECS/k8s resources (`*.tf`).
- **Tilt/Bazel/Skaffold/Earthly**: build DSLs reference images in plain
  strings (`custom_build`, `docker_build`, `helm_resource` chart versions).

### 5.4 Renamed Dockerfiles

Content-sniff for files whose early lines are `# syntax=`/comments/ARG
followed by `FROM ` regardless of filename. (Ours found only false
positives — but the check is one grep, and a renamed Dockerfile would
evade every name-based pass.)

## 6. Verify with adversarial probes — the most important step

The passes above will have bugs. Ours did — four of them. The technique
that found every one: **pick an image you know your org uses and trace it
through all files**, then explain every hit the report doesn't contain.

```bash
grep -rni '<image-name>' . | grep -viE 'node_modules|…'
```

Each unexplained hit is either a false negative (fix the detector, then
re-sweep the *whole org* for that pattern class, not just the one hit) or
a correct exclusion (pinned, not an image, out of scope — say why).
Probe with names from different ecosystems: an infra image (`localstack`),
common services (`nginx`, `redis`, `postgres`), something niche you saw in
a Dockerfile. Stop when probes keep coming back explained.

Grep-filter bugs we hit, so you can avoid them:

1. Excluding ` AS ` lines from Dockerfile FROMs (deleted real findings).
2. Path-based exclusion patterns (`-v 'tilt/'`) matching the *file path*
   prefix in grep output and silently discarding every hit in the
   directory being searched.
3. `$`-anchored patterns applied to multi-column output (the tag column
   wasn't at end-of-line; findings vanished).
4. A generic `reference:` key colliding with 800+ dbt column definitions.

The meta-lesson: complex chained `grep -v` filters fail silently. Prefer
short, readable patterns plus manual skim, or a real parser. And always
test a detector against a **known positive** before trusting its output.

## 7. Triage and reporting

Score each finding as *mutability class* (§3) × *execution context*:

- **P0** — runs in CI with credentials (job containers, services, inline
  docker-run in workflows), in production desired state, or in shared
  infrastructure (self-hosted runner images, cluster controllers).
- **P1** — developer machines: compose files, dev-CLIs mounting
  credentials, local charts. (Dev machines are the actual blast radius of
  token-stealing worms — don't dismiss this tier.)
- **P2** — demos, sandboxes, dead pipelines. Often the fix is archiving
  the repo, not editing it.

Flag separately, regardless of tag: **personal-account images**
(`someuser/tool` on Docker Hub) and **abandoned namespaces**
(`bitnamilegacy/…`) in anything that executes — those are supply-chain
risks even when version-pinned. Deliver a per-row table (repo, file:line,
image, note) — checklists get actioned; prose gets read once.

State the residual blind spots honestly. For grep-level scanning they are:
tags injected at deploy time by CI/gitops (an empty `tag:` in values tells
you nothing about production), upstream chart defaults, template-composed
image strings, non-default branches, and archived repos. Closing those
requires a YAML-parsing scanner and, for gitops, resolving your Argo/Flux
overlay pattern — decide whether the marginal findings justify it after
the grep pass lands.

## 8. Remediation quick reference

- Pin by digest: `image:1.2.3@sha256:…` (tag kept for readability; digest
  is what's enforced). Renovate/Dependabot both support automated digest
  bumps, so pinning doesn't mean freezing.
- Fix the highest-leverage single point first: shared/reusable CI images
  and workflows — one digest pin there covers every consuming repo.
- Replace personal-account images with official images or an org-controlled
  mirror (ECR pull-through cache), then pin the mirror.
