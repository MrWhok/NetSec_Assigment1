FLOW TO REPLICATE:

1. `docker-compose up --build` (in this folder)
2. run `script.md` in this folder to obtain client-id and client-secret (cek apakah container up apa ga dl)
3. go to `../webapp-jelek/app.py` -> ganti line 12 & 13 (ada NOTE nya) sama client-id dan client-secret
4. `docker-compose up --build` (di folder webapp-jelek)

ARCHITECTURE:
webapp-jelek -> ory-hydra -> mock-ui -> ???

semuanya containerized, terhubung sama netsec-bridge
