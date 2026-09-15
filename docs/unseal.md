# Initialize & unseal

On startup EasyVault is **sealed**: the database is present but the master key is
not in memory, so nothing can be decrypted and secret requests are refused. This
happens on **every restart** — the same model as HashiCorp Vault — so after a
reboot or upgrade you unseal again.

## First run

=== "In the browser"

    Open `http://<host>:8200`. A fresh instance walks you through it:

    1. **Initialize** — choose the number of key shares and the threshold
       (default **5 shares, 3 required**). The shares are shown **once** — save
       them somewhere safe.
    2. **Unseal** — paste shares one at a time until the threshold is met.
    3. **Create the master account**, then sign in.

=== "Over the REST API"

    ```bash
    # Initialize once — returns the unseal shares (save them!)
    curl -X POST http://<host>:8200/v1/sys/init \
      -H 'Content-Type: application/json' \
      -d '{"secret_shares":5,"secret_threshold":3}'

    # Unseal after every restart — one call per share, until the threshold is met
    curl -X POST http://<host>:8200/v1/sys/unseal \
      -H 'Content-Type: application/json' -d '{"key":"<share-1>"}'
    curl -X POST http://<host>:8200/v1/sys/unseal \
      -H 'Content-Type: application/json' -d '{"key":"<share-2>"}'
    curl -X POST http://<host>:8200/v1/sys/unseal \
      -H 'Content-Type: application/json' -d '{"key":"<share-3>"}'

    # Check status
    curl http://<host>:8200/v1/sys/seal-status
    ```

    Then open the dashboard to create the master account.

!!! warning "Keep your unseal shares safe"
    The shares are shown only at init. Lose more than `shares − threshold` of
    them and the data is **unrecoverable**; anyone holding `threshold` of them can
    unseal the instance. Store them with different people, or in different places.

## After a restart

Opening the dashboard on a sealed instance takes you straight to the unseal
form. Enter shares until the threshold is met and you are dropped back into the
app; API clients can unseal with `/v1/sys/unseal` exactly as above.

Monitoring can poll `GET /v1/sys/health` — `200` unsealed, `503` sealed, `501`
not yet initialized — or `GET /v1/sys/seal-status`. Neither needs a token.

## Emergency seal

A master operator can **seal the instance** from the dashboard at any time. The
master key is dropped from memory immediately: every token stops working and
every signed-in user is locked out until the instance is unsealed again with the
shares. Use it when you suspect a compromise.

Next: [how the keys fit together](security.md).
