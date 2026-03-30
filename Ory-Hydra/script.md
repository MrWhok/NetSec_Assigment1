buat ambil creds client:

```
docker exec ory-hydra-hydra-1 hydra create client --endpoint http://127.0.0.1:4445 --grant-type authorization_code,refresh_token --response-type code,id_token --format json --scope openid,offline_access,profile,email --redirect-uri http://127.0.0.1:5000/callback --redirect-uri http://localhost:5000/callback
```

NOTE: GANTI ory-hydra-hydra-1 dengan container name
