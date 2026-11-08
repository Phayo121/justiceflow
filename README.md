# JusticeFlow — authenticated case administration starter

This project is an independent, local full-stack starter for Eswatini justice workflow exploration. It will have a public landing page and rights reference, sign-in for staff accounts, separate police/prosecution/court/corrections/admin workspaces, server-side role checks, and persistent SQLite case/activity records.

## Run locally

Requires Node.js 22.13+ (uses the built-in `node:sqlite` module; the project installs no third-party packages).

```powershell
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). The server binds to loopback by default. Records are stored in `data/justice.sqlite`. To select another database file, set `JUSTICE_DB_PATH` before starting the server.

Create the first administrator in an interactive terminal:

```powershell
npm run create-admin
```

The command prompts for a username, display name, and password (Hidden while entered). Passwords must be at least 12 characters. It refuses to create another administrator unless `ALLOW_ADDITIONAL_ADMIN=true` is explicitly set.

The administrator signs in at `/login` and creates Police, Prosecution, Court, and Corrections accounts. The admin supplies a unique username and temporary password to each staff member through an approved secure channel. Each staff member must change the temporary password before opening a workspace. There is deliberately no public signup and no built-in sample case data.

## Workspaces and API

- `/police` — create initial case records; view police-intake records; refer a case to prosecution.
- `/prosecution` — view referred cases; record court referral or administrative closure.
- `/court` — view court-stage cases; record custody handoff or administrative closure.
- `/corrections` — view custody cases and record administrative closure.
- `/admin` — create accounts only; administrators cannot view case records.
- `GET /api/session`, `POST /api/login`, `POST /api/logout`, `POST /api/password`
- `GET /api/cases`, `POST /api/cases`, `GET /api/cases/:id`, `POST /api/cases/:id/handoff`
- `POST /api/admin/users`

Case-stage transitions and access are enforced on the server, not just hidden in the interface. Each agency sees only its current-stage records; a closed record remains visible only to the agency role that closed it. Passwords are salted and hashed with scrypt; session tokens are random, held in HttpOnly/SameSite cookies, and stored as hashes. Database writes include case activity and audit events. The server applies request-size limits, basic login throttling, input validation, and browser security headers.

## Constitutional information

The landing page links to a secondary online copy of the *Constitution of the Kingdom of Swaziland Act, 2005* (now Eswatini), Chapter III, Fundamental Rights and Freedoms, and provides a high-level rights overview. Treat that page as an orientation only. Verify the current authoritative text and amendments through official Eswatini sources and qualified counsel. The overview is not legal advice and does not replace agency procedures.

## Critical limitations — not production-ready

“Real backend” here means local persistent storage and authenticated, role-checked application flows. It does **not** make this suitable for operational justice records. Do not enter real names, allegations, evidence, custody information, or other sensitive case data.

Before any real-world pilot, the competent Eswatini authorities and counsel must validate legal authority, roles, disclosure and access boundaries, due-process safeguards, records and retention rules, data protection requirements, and every handoff. Production deployment additionally requires an approved HTTPS reverse proxy and secure cookies, managed secret/key operations, stronger identity/MFA and account recovery, formal authorization reviews, tamper-evident audit retention and monitoring, encrypted and tested backups, vulnerability/security testing, incident response, and agency integration approval. The included audit table is an initial application log, not a certified tamper-proof audit system. The application does not decide arrest, charging, guilt, bail, sentence, or release.

The prototype has an administrator-seeding command, but no account-recovery or MFA flow. Back up the SQLite database securely; it contains password hashes, account records, case records, and audit history.

## Validation

```powershell
npm run check
npm test
```

## Copyright and use

© 2026 Ndlovu Dumisa, Mkhatshwa Fisokuhle, Ginindza Nkosephayo, Khumalo Owenkhosi, Magagula Sibonelo. All rights reserved. Submitted for CSC411, University of Eswatini.

This work is submitted for assessment in CSC411 only. It may not be published, copied or reused without the authors' written permission.
