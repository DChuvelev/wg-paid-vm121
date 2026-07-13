
## 2026-07-06 - MGTS WG Paid post-smoke deferred tasks

### Production endpoint

Current backend `.env` uses internal smoke endpoint:

    WG_CLIENT_ENDPOINT=wg-studio.secret-studio.ru:51830

Before production client delivery, replace with the real external MGTS endpoint / DNS that reaches:

    VM101 DNAT UDP 51830 -> MGTS VM100 10.71.100.1:51830

### Backend container dependencies

`docker compose up -d --force-recreate backend` recreated the backend from `python:3.12-slim`.
The container installs dependencies at runtime/startup. During restart, backend temporarily failed until `cryptography` and other packages were available.

Make this persistent later:

- add/restore requirements.txt or pyproject;
- build a real backend image with dependencies baked in;
- avoid relying on manual `pip install` inside a running container;
- make `docker compose up -d --force-recreate backend` safe and repeatable.


<!-- STEP_034E4D_ENDPOINT_TASK_RESOLVED_BEGIN -->
Endpoint migration note, added 2026-07-08 11:55:55:
- WG Paid public client endpoint source is now: wg-studio.secret-studio.ru:51830
- Active source file: /opt/wg-access/.env
- Internal DNAT target remains intentionally internal: VM101 UDP 51830 -> VM100 10.71.100.1:51830
- Historical STATUS/tmp/backups may still mention older smoke endpoints; those are not active source.
- Running backend container must be restarted/recreated separately before it reads the new .env.
<!-- STEP_034E4D_ENDPOINT_TASK_RESOLVED_END -->
