#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect.py — tech stack detector + FULL recommendations (SAST/SCA/DAST/etc.) with categories.
- Safe syntax (no tricky quoting), color optional, and ALWAYS prints the full list for each detected tech.
- Generates optional JSON and a runnable next-steps.sh with ALL commands.
"""

from __future__ import annotations
import argparse, json, os
from pathlib import Path
from collections import Counter, defaultdict

# ---------- Color helpers ----------
RESET = "\033[0m"; BOLD="\033[1m"; BLUE="\033[94m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; MAGENTA="\033[95m"; GREY="\033[90m"
def cz(s, color, use): return f"{color}{s}{RESET}" if use else s
def header(title, use): 
    bar = "-"*66
    print(cz(bar, GREY, use)); print(cz(title, BOLD, use)); print(cz(bar, GREY, use))

# ---------- Skip dirs & heuristics ----------
SKIP_DIRS = {".git",".hg",".svn",".idea",".vscode","node_modules","vendor","dist","build","out","target","__pycache__", ".next",".nuxt",".cache",".tox",".mypy_cache"}

MANIFEST_RULES = {
    "package.json":{"ecosystem":"nodejs"},"package-lock.json":{"ecosystem":"nodejs"},"yarn.lock":{"ecosystem":"nodejs"},"pnpm-lock.yaml":{"ecosystem":"nodejs"},
    "tsconfig.json":{"ecosystem":"typescript"},"deno.json":{"ecosystem":"deno"},
    "requirements.txt":{"ecosystem":"python"},"pyproject.toml":{"ecosystem":"python"},"Pipfile":{"ecosystem":"python"},
    "pom.xml":{"ecosystem":"java"},"build.gradle":{"ecosystem":"java"},"build.gradle.kts":{"ecosystem":"kotlin"},
    "go.mod":{"ecosystem":"go"},"Cargo.toml":{"ecosystem":"rust"},"composer.json":{"ecosystem":"php"},"Gemfile":{"ecosystem":"ruby"},
    ".sln":{"ecosystem":"dotnet"},".csproj":{"ecosystem":"dotnet"},
    "Dockerfile":{"container":"docker"},"docker-compose.yml":{"container":"docker-compose"},"compose.yaml":{"container":"docker-compose"},
    ".gitlab-ci.yml":{"ci":"gitlab-ci"},"azure-pipelines.yml":{"ci":"azure-pipelines"},"cloudbuild.yaml":{"ci":"gcp-cloud-build"},
    "main.tf":{"iac":"terraform"},"Chart.yaml":{"iac":"helm"},"chart.yaml":{"iac":"helm"},"kustomization.yaml":{"iac":"kustomize"},
    "openapi.yaml":{"api":"openapi"},"openapi.yml":{"api":"openapi"},"openapi.json":{"api":"openapi"},
    "swagger.yaml":{"api":"openapi"},"swagger.yml":{"api":"openapi"},"swagger.json":{"api":"openapi"},
}
EXT_LANG = {".ts":"typescript",".tsx":"typescript",".js":"javascript",".jsx":"javascript",".py":"python",".java":"java",".kt":"kotlin",".go":"go",".rs":"rust",".php":"php",".rb":"ruby",".cs":"csharp",".yaml":"yaml",".yml":"yaml",".tf":"terraform",".groovy":"groovy",".gradle":"gradle",".sln":"dotnet",".csproj":"dotnet",".graphql":"graphql",".gql":"graphql"}

# Framework hints (simple substrings)
FRAMEWORK_HINTS = [
    ("require('express')","express"),("from django","django"),("import flask","flask"),("from fastapi","fastapi"),
    ("org.springframework","spring"),("github.com/gin-gonic/gin","gin"),("github.com/labstack/echo","echo"),
    ("Illuminate\\\\","laravel"),("Symfony\\\\Component","symfony"),("Rails.","rails"),("next.config.js","nextjs"),("defmodule","phoenix")
]

# ---------- Recommendations (command, why, [CATEGORY]) ----------
RECS = {
    "_universal":[
        ("gitleaks detect -v -r gitleaks.json .","Scan for committed secrets","SECRETS"),
        ("trufflehog filesystem --only-verified . > trufflehog.txt","Verify potential secrets","SECRETS"),
        ("syft dir:. -o json > sbom.json","Generate SBOM (inventory)","SUPPLY"),
        ("osv-scanner -r .","Dependency vulnerabilities (multi-ecosystem)","SCA"),
        ("licensee detect . || true","Detect licenses / issues (optional)","LICENSE"),
    ],
    "nodejs":[
        ("npm install --ignore-scripts || true","Install deps safely (no postinstall)","SUPPLY"),
        ("npm ci --ignore-scripts || true","Clean install from lockfile (CI safe)","SUPPLY"),
        ("npm ls || true","Detect unmet/missing dependencies","SUPPLY"),
        ("npx depcheck || true","Find missing/unused deps in code","SUPPLY"),
        ("npm audit || true","Audit npm vulnerabilities","SCA"),
        ("npx snyk test || true","Snyk test (if installed/auth)","SCA"),
        ("npx retire || true","Detect vulnerable front-end libs","SCA"),
        ("semgrep --config p/ci","SAST for JS/TS security patterns","SAST"),
        ("eslint . || true","Static linting (if configured)","LINT"),
        ("npx license-checker --summary || true","License summary","LICENSE"),
        ("npx npm-check-updates -u || true","Suggest dependency updates","SUPPLY"),
        ("yarn audit || true","If Yarn: audit vulnerabilities","SCA"),
        ("pnpm audit || true","If pnpm: audit vulnerabilities","SCA"),
    ],
    "typescript":[
        ("tsc -p tsconfig.json --noEmit || true","Type-check TS project","LINT"),
        ("semgrep --config p/ci","SAST for TypeScript","SAST"),
    ],
    "deno":[("deno lint || true","Static linting","LINT"),("deno check **/*.ts || true","Type-check modules","LINT")],
    "python":[
        ("python -m pip install -r requirements.txt -q || true","Install Python deps","SUPPLY"),
        ("pip-audit || true","Dependency CVEs","SCA"),
        ("safety check || true","Alternate dependency CVE scan","SCA"),
        ("pip check || true","Dependency conflicts","SUPPLY"),
        ("pipdeptree --warn fail || true","Detect dependency issues","SUPPLY"),
        ("bandit -r . || true","SAST for Python","SAST"),
        ("ruff . || true","Fast linter","LINT"),
        ("pylint **/*.py || true","Lint/analysis","LINT"),
    ],
    "java":[
        ("mvn -q versions:display-dependency-updates || true","Outdated Maven deps","SUPPLY"),
        ("mvn -q org.owasp:dependency-check-maven:check || true","OWASP Dependency-Check","SCA"),
        ("osv-scanner -r .","Cross-check deps via OSV","SCA"),
        ("mvn -q com.github.spotbugs:spotbugs-maven-plugin:spotbugs || true","SpotBugs static analysis","SAST"),
        ("mvn -q com.github.spotbugs:spotbugs-maven-plugin:spotbugs -Dplugin.artifact=com.h3xstream.findsecbugs:findsecbugs-plugin:1.12.0 || true","FindSecBugs rules","SAST"),
        ("semgrep --config p/java","SAST rules (Java/Groovy)","SAST"),
        ("checkstyle -c /google_checks.xml -f xml -o checkstyle.xml || true","Style/lint","LINT"),
        ("pmd -d src -R category/java/security.xml -f text || true","PMD security rules","SAST"),
    ],
    "kotlin":[("osv-scanner -r .","Known vulns in Kotlin/JVM deps","SCA"),("semgrep --config p/java","SAST (JVM patterns)","SAST")],
    "groovy":[("semgrep --config p/java","SAST for Groovy/Java patterns","SAST")],
    "go":[
        ("govulncheck ./... || true","Go vulnerability scan","SCA"),
        ("gosec ./... || true","SAST for Go","SAST"),
        ("staticcheck ./... || true","Static analysis","LINT"),
        ("go vet ./... || true","Vet code issues","LINT"),
        ("osv-scanner -r .","Cross-check via OSV","SCA"),
    ],
    "rust":[("cargo audit || true","Crate vulnerabilities","SCA"),("cargo deny check || true","Advisories, bans, licenses","SCA"),("cargo clippy || true","Lint/analysis","LINT")],
    "php":[
        ("composer install --no-scripts || true","Safe install (no scripts)","SUPPLY"),
        ("composer audit || true","Vulnerable dependencies","SCA"),
        ("local-php-security-checker || true","Security check without API","SCA"),
        ("phpstan || true","Static analysis","SAST"),
        ("psalm || true","Static analysis","SAST"),
    ],
    "ruby":[("bundle install || true","Install gems","SUPPLY"),("bundle audit || true","Vulnerable gems","SCA"),("brakeman || true","Rails security scanner","SAST"),("rubocop || true","Lint/analysis","LINT")],
    "dotnet":[
        ("dotnet restore || true","Restore packages","SUPPLY"),
        ("dotnet list package --vulnerable || true","Vulnerable NuGet packages","SCA"),
        ("dotnet build -warnaserror || true","Enable analyzers warnings as errors","LINT"),
        ("devskim analyze . || true","Microsoft DevSkim SAST","SAST"),
        ("osv-scanner -r .","Cross-check via OSV","SCA"),
    ],
    "docker":[("trivy fs . || true","Scan Dockerfiles and filesystem","CONTAINER"),("dockle . || true","Dockerfile best practices","CONTAINER"),("hadolint Dockerfile || true","Dockerfile linter","CONTAINER")],
    "docker-compose":[("trivy config . || true","Scan compose config","CONTAINER")],
    "terraform":[("tfsec . || true","Terraform security scan","IAC"),("checkov . || true","IaC scanner (Terraform)","IAC"),("terrascan scan . || true","Alternate IaC scanner","IAC")],
    "helm":[("trivy config . || true","Scan Helm charts","IAC")],
    "kustomize":[("trivy config . || true","Scan Kustomize configs","IAC")],
    "yaml":[("trivy config . || true","Scan YAML configs","IAC"),("kube-linter . || true","K8s manifest lint","IAC"),("kube-score score . || true","K8s static analysis","IAC"),("polaris audit . || true","K8s policy audit","IAC")],
    "github-actions":[
        ("actionlint || true","Lint GitHub Actions","CI"),
        ("grep -R pull_request_target .github/workflows || true","Find dangerous PR triggers","CI"),
        ("grep -R '@main' .github/workflows || true","Find unpinned actions","CI"),
        ("grep -R 'secrets.' .github/workflows || true","Audit secret usage","CI"),
    ],
    "gitlab-ci":[("trivy config . || true","Scan GitLab CI config","CI")],
    "azure-pipelines":[("trivy config . || true","Scan Azure Pipelines config","CI")],
    "gcp-cloud-build":[("trivy config . || true","Scan GCP Cloud Build config","CI")],
    "openapi":[
        ("spectral lint **/openapi*.y*ml **/swagger*.y*ml || true","Lint OpenAPI/Swagger","API"),
        ("oasdiff breaking base.yaml revision.yaml || true","Breaking change check (example)","API"),
        ("schemathesis run --checks all http://localhost:8000/openapi.json || true","Fuzz API from schema (example URL)","DAST"),
    ],
    "graphql":[
        ("graphql-inspector validate schema.graphql operations/**/*.graphql || true","Validate operations vs schema","GRAPHQL"),
        ("python3 -m pip install inql && inql -t http://localhost:4000/graphql || true","Explore GraphQL (example URL)","GRAPHQL"),
        ("graphql-cop -t http://localhost:4000/graphql || true","Security tests (example URL)","DAST"),
    ],
    "_web_dast":[
        ("nuclei -u http://localhost -as || true","Template-based web scan (example URL)","DAST"),
        ("zap-baseline.py -t http://localhost -r zap.html || true","OWASP ZAP baseline scan","DAST"),
        ("nikto -h http://localhost || true","Basic web server scan","DAST"),
        ("testssl.sh --fast localhost || true","TLS/SSL checks","DAST"),
        ("sqlmap -u http://localhost/?id=1 --batch || true","SQL injection testing (example URL & param)","DAST"),
    ],
}
SECTION_LABELS = {
    "_universal":("Universal checks",BLUE),"nodejs":("Node.js / TypeScript",GREEN),"typescript":("TypeScript",GREEN),
    "deno":("Deno",GREEN),"python":("Python",GREEN),"java":("Java / Groovy / Kotlin",GREEN),"kotlin":("Kotlin",GREEN),
    "groovy":("Groovy",GREEN),"go":("Go",GREEN),"rust":("Rust",GREEN),"php":("PHP",GREEN),"ruby":("Ruby",GREEN),
    "dotnet":(".NET",GREEN),"docker":("Docker",CYAN),"docker-compose":("Docker Compose",CYAN),"terraform":("Terraform",CYAN),
    "helm":("Helm",CYAN),"kustomize":("Kustomize",CYAN),"yaml":("YAML / K8s Manifests",YELLOW),"github-actions":("GitHub Actions",MAGENTA),
    "gitlab-ci":("GitLab CI",MAGENTA),"azure-pipelines":("Azure Pipelines",MAGENTA),"gcp-cloud-build":("GCP Cloud Build",MAGENTA),
    "openapi":("OpenAPI / Swagger",BLUE),"graphql":("GraphQL",BLUE),"_web_dast":("Generic Web DAST (provide target URL)",YELLOW),
}

def is_textual(p: Path)->bool:
    return p.suffix.lower() in {".json",".js",".ts",".tsx",".jsx",".yml",".yaml",".toml",".xml",".html",".md",".txt",".cfg",".ini",".groovy",".gradle",".rb",".py",".java",".go",".rs",".php",".cs",".scala",".swift",".ex",".exs",".kts",".graphql",".gql"}

def iter_files(root: Path):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for n in fns: yield Path(dp)/n

def scan(path: Path)->dict:
    found = {"root":str(path.resolve()),"files_scanned":0,"languages":Counter(),"ecosystems":Counter(),"frameworks":Counter(),"containers":Counter(),"iac":Counter(),"ci_cd":Counter(),"cloud_hints":Counter(),"api_specs":Counter(),"manifests":defaultdict(list)}
    def mark_manifest(fname: str, fp: Path):
        rule = MANIFEST_RULES.get(fname); 
        if not rule: return
        for k,v in rule.items():
            if k=="ecosystem": found["ecosystems"][v]+=1
            elif k=="container": found["containers"][v]+=1
            elif k=="iac": found["iac"][v]+=1
            elif k=="ci": found["ci_cd"][v]+=1
            elif k=="api": found["api_specs"][v]+=1
        found["manifests"][fname].append(str(fp.relative_to(path)))
    for f in iter_files(path):
        found["files_scanned"]+=1
        ext = f.suffix.lower()
        if ext in EXT_LANG: found["languages"][EXT_LANG[ext]]+=1
        base = f.name
        if base in MANIFEST_RULES or base.endswith(".sln") or base.endswith(".csproj"):
            key = base if base in MANIFEST_RULES else (".sln" if base.endswith(".sln") else ".csproj")
            mark_manifest(key,f)
        if ".github/workflows" in str(f):
            found["ci_cd"]["github-actions"]+=1; found["manifests"][".github/workflows"].append(str(f.relative_to(path)))
        if base=="Dockerfile" or base.startswith("Dockerfile."):
            found["containers"]["docker"]+=1; found["manifests"]["Dockerfile"].append(str(f.relative_to(path)))
        if is_textual(f):
            try: txt = f.read_text(encoding="utf-8",errors="ignore")
            except Exception: continue
            low = txt.lower()
            for needle,fw in FRAMEWORK_HINTS:
                if needle.lower() in low: found["frameworks"][fw]+=1
            if ("openapi:" in low) and (f.suffix.lower() in {".yml",".yaml"}): found["api_specs"]["openapi"]+=1
            if ("type query" in low or "schema{" in low) and f.suffix.lower() in {".graphql",".gql"}: found["languages"]["graphql"]+=1
            if "arn:aws" in txt or "aws_" in low: found["cloud_hints"]["aws"]+=1
            if "googleapis.com" in txt or "gcp_" in low or "gcloud" in low: found["cloud_hints"]["gcp"]+=1
            if "azure.com" in txt or "azure_" in low: found["cloud_hints"]["azure"]+=1
            if f.suffix.lower() in {".yml",".yaml"} and ("apiversion:" in low) and any(k in low for k in ["deployment","service","ingress"]):
                found["iac"]["kubernetes-manifest"]+=1
            if f.suffix.lower()==".tf": found["iac"]["terraform"]+=1
    def top(c: Counter,n=100): return [{"name":k,"count":v} for k,v in c.most_common(n)]
    return {"root":found["root"],"files_scanned":found["files_scanned"],"languages":top(found["languages"]),"ecosystems":top(found["ecosystems"]),"frameworks":top(found["frameworks"]),"containers":top(found["containers"]),"infrastructure_as_code":top(found["iac"]),"ci_cd":top(found["ci_cd"]),"cloud_hints":top(found["cloud_hints"]),"api_specs":top(found["api_specs"]),"manifests":{k:v for k,v in sorted(found["manifests"].items())}}

def group_recs(report: dict)->dict[str,list[tuple[str,str,str]]]:
    groups = {"_universal": RECS.get("_universal",[])[:]}
    def add(bucket_key: str):
        for item in report.get(bucket_key,[]):
            name = item["name"]
            if name in RECS: groups.setdefault(name,[]).extend(RECS[name])
    for key in ["ecosystems","languages","containers","infrastructure_as_code","ci_cd","api_specs"]:
        add(key)
    web_fw = {"express","django","flask","fastapi","spring","gin","echo","laravel","symfony","rails","nextjs","phoenix"}
    if any(i["name"] in web_fw for i in report.get("frameworks",[])): groups.setdefault("_web_dast",[]).extend(RECS["_web_dast"])
    # dedup by command
    for k,v in list(groups.items()):
        seen=set(); ded=[]
        for cmd,why,cat in v:
            if cmd not in seen: ded.append((cmd,why,cat)); seen.add(cmd)
        groups[k]=ded
    return groups

def main():
    ap = argparse.ArgumentParser(description="Detect tech stack & print FULL grouped recommendations with categories.")
    ap.add_argument("path", nargs="?", default=".", help="Root path to scan")
    ap.add_argument("--json", dest="json_out", help="Write JSON report")
    ap.add_argument("--script", dest="script_out", help="Write a runnable next-steps.sh")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.exists(): print(f"Path not found: {root}"); raise SystemExit(2)
    use = os.isatty(1) and not args.no_color

    report = scan(root)

    print("="*72); print(f"Tech Stack Report for: {report['root']}"); print("="*72)
    def fmt(b): return ", ".join([f"{x['name']} ({x['count']})" for x in b]) or "—"
    print(f"Files scanned        : {report['files_scanned']}")
    print(f"Languages            : {fmt(report['languages'])}")
    print(f"Ecosystems           : {fmt(report['ecosystems'])}")
    print(f"Frameworks           : {fmt(report['frameworks'])}")
    print(f"Containers           : {fmt(report['containers'])}")
    print(f"IaC                  : {fmt(report['infrastructure_as_code'])}")
    print(f"CI/CD                : {fmt(report['ci_cd'])}")
    print(f"Cloud hints          : {fmt(report['cloud_hints'])}")
    print(f"API specs            : {fmt(report['api_specs'])}")

    if report["manifests"]:
        print("\nManifests discovered:")
        for k,paths in report["manifests"].items():
            show = ", ".join(paths[:3]); more = "" if len(paths)<=3 else f" (+{len(paths)-3} more)"
            print(f"  - {k}: {show}{more}")

    header("Recommended Next Steps", use)
    groups = group_recs(report)
    ordered = ["_universal"] + sorted([k for k in groups if k!="_universal"])
    for key in ordered:
        label,color = SECTION_LABELS.get(key,(key,BOLD))
        print(cz(f"\n{label}", color, use))
        for cmd,why,cat in groups[key]:
            print(f"  - {cmd}\n      [{cat}] {why}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2)); print(f"\nJSON written to: {Path(args.json_out).resolve()}")
    if args.script_out:
        lines = ["#!/usr/bin/env bash","set -euo pipefail","echo 'Running recommended checks...'"]
        for key in ordered:
            for cmd,_,_ in groups[key]: lines.append(cmd)
        sp = Path(args.script_out); sp.write_text("\n".join(lines)+"\n"); os.chmod(sp,0o755); print(f"Next-steps script written to: {sp.resolve()}")

if __name__ == "__main__":
    main()
