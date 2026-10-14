# Governance Layer Endpoints

Use either `/api/v1` or `/governance` before these paths.

| Method | Endpoint | What it does | Where it goes |
|---|---|---|---|
| `GET` | `/data-providers` | Lists available data providers. | Reads provider data from PostgreSQL. |
| `PUT` | `/provider-keys/{role}` | Registers (or replaces) the caller's contract-signing public key. Body: `{"public_key_pem": "..."}`. | Checks the caller's Keycloak token and role, then writes the key to PostgreSQL. |
| `GET` | `/provider-keys/{role}/status` | Shows whether the caller has a public key registered. | Checks the caller's Keycloak token, then reads the key from PostgreSQL. |
| `POST` | `/send-provider-message` | Saves a message for a provider. | Writes the message to PostgreSQL. |
| `POST` | `/notifications` | Creates participation requests for providers. | Writes notifications to PostgreSQL. |
| `GET` | `/notifications/{key}` | Gets notifications for one provider. | Reads notifications from PostgreSQL. |
| `GET` | `/notifications/by-sender/{key}` | Gets replies to requests sent by an owner. | Reads notifications from PostgreSQL. |
| `PATCH` | `/notifications/{key}/read` | Marks a notification as read. | Updates the notification in PostgreSQL. |
| `POST` | `/notifications/{key}/respond` | Saves a provider's accepted or declined response. | Updates PostgreSQL notifications and, for an accepted request, the provider's contract record. |
| `POST` | `/contract` | Checks a signed contract and selects the FL, TEE, or SMPC path. | Checks Keycloak, reads policies from APD, and stores or starts the selected process. |
| `GET` | `/contract/{sessionId}` | Gets the saved contract for a session. | Reads the contract from PostgreSQL. |
| `POST` | `/contracts` | Creates and saves an FL draft or final contract. | Reads submission data and writes contracts/projects to PostgreSQL. |
| `GET` | `/contracts/by-project/{projectId}` | Gets the contract for one project. | Reads the contract from PostgreSQL. |
| `POST` | `/contracts/{contractId}/sign` | A data provider submits their signature over the contract hash, using their own token. Replies `{"status": "signed"}` or `{"status": "not signed", "message": ...}`. | Checks the signer's Keycloak token, re-hashes the stored contract, and verifies the signature with the key registered at `PUT /provider-keys/{role}`. |
| `GET` | `/contracts/{contractId}/signatures` | Shows each data provider's signing state, plus `all_signed`. | Reads the contract from PostgreSQL and re-verifies signers against Keycloak. |
| `GET` | `/contracts/by-session/{sessionId}/signatures` | The same signing state, for a session's latest contract. p3dx-aaa checks this before starting an FL session. | Reads the session's contract from PostgreSQL and re-verifies signers against Keycloak. |
| `GET` | `/projects/{sessionId}` | Finds the project ID for a session. | Reads project data from PostgreSQL. |
| `GET` | `/projects?owner={username}` | Lists projects for an owner, or all projects for the operator. | Reads projects from PostgreSQL. |
| `POST` | `/generate-contract` | Creates an unsigned contract preview. | Checks Keycloak, reads policies/forms from APD, and saves the draft in PostgreSQL. |
| `POST` | `/job/approval/data-provider` | A data provider approves a job. Body: `{"job_id", "contract_hash", "signature"}`. | Checks the caller's token and their own datasets on the job's contract, verifies and stores the signature, and posts consumer grants to APD. |
| `POST` | `/job/approval/infra-provider` | An infra provider approves a job, with the same body. Returns `403` if the caller owns none of the job's infras. | Checks the caller's token and their own infras on the contract, then verifies and stores the signature. |
| `PUT` | `/job/{jobId}/status` | The job's consumer checks that every provider approved and that every signature matches gov_layer's copy of the contract. Anyone else gets `403`. | Checks the consumer's token, reads approvals and the contract from PostgreSQL, and verifies each signature with the registered public keys. |
| `POST` | `/job/{jobId}/tee` | The job's consumer enables the TEE run. It starts nothing; the run itself is `POST /v1/tee/sessions`. | Checks the consumer's token, re-verifies every signature on the final contract, and marks the job TEE-enabled in PostgreSQL. |
| `GET` | `/job/{jobId}/contract/{contractId}` | Gets a job's contract and its `contract_hash`. Only the job's consumer or providers may read it (`403 NOT_JOB_PARTICIPANT`). | Checks the caller's token and reads the contract from PostgreSQL. |
| `GET` | `/jobs/user/{userId}` | Lists every job the user takes part in, as consumer or provider, newest first, with their status on each. | Checks the caller's token and reads jobs from PostgreSQL. |
| `GET` | `/final-models` | Lists the latest model for each FL session. | Reads model files from the local checkpoint folder. |
| `GET` | `/final-model/download?session_id=&round=` | Downloads an FL model. Defaults to the newest session's final round. | Reads the selected model file from local storage. |
| `GET` | `/final-model/summary?session_id=&round=` | Shows details about an FL model. | Reads the model file and runs the local model inspector. |
| `POST` | `/vm-registry` | Registers a participant VM and its IP address. Needs the `X-VM-Registry-Token` header when a token is configured. | Writes the VM record to PostgreSQL. |
| `GET` | `/vm-registry/output-owner` | Finds the output-owner VM. Same token header. | Reads the VM record from PostgreSQL. |
| `GET` | `/vm-registry/data-providers` | Lists all data-provider VMs. Same token header. | Reads VM records from PostgreSQL. |
