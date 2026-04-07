#-----------------------------------------------------
The Keyfactor Vault Secrets Engine acts like an event router:

- Vault emits certificate‑related events →
- the plugin transforms them into Keyfactor API calls →
- Keyfactor issues or manages certificates →
- results flow back into Vault’s secrets store.

Everything is driven by requests, policy checks, and responses,
not by long‑running stateful processes.

# 1. Event: Vault loads and configures the plugin
Trigger:
vault secrets enable keyfactor
vault write keyfactor/config ...

Plugin reaction:
- Register itself as a PKI-like secrets engine.
- Stores configuration (Keyfactor URL, CA, template, auth method)
- Validates connectivity/authentication to Keyfactor on-demand, not continiously

Outcome:
The plugin becoms an event listener for certificate-related Vault API calls.

# 2. Event: A client requests a certificate
Example:
vault write keyfactor/issue/hashiwebserver common_name=foo.kftrain.lab

Trigger:
Vault receives a write request to the /issue/<role> endpoint.

Plugin reaction pipeline:

1. Vault policy check
Vault checks ACL:
Is this token allowed to call this role ?

2. Role evaluation
Plugin loads the role definition:
- allowed_domains
- allow_subdomains

3. Domain validation event
Plugin checks:
Does the requested CN/SAN fall within allowed domains?

4. Keyfactor request event
Plugin constructs a Keyfactor enrollment request using:
- CA name
- Template name
- CSR (generated internally or provided)
- Metadata (optional)
- Authentication (basic, OAuth, or access token)

5. Keyfactor issuance event
Keyfactor Command:
- Applies template rules
- Applies CA issuance policy
- Issues certificate
- Returns certificate + metadata

6. Vault storage event
Plugin stores the certificate in Vault’s secrets store under /certs/<serial>.

Outcome:
Vault returns the certificate bundle to the caller and retains a copy for later retrieval.

# 3. Event: A client reads a certificate

vault read keyfactor/cert/<serial>

Trigger:
Vault receives a read request for a stored certificate.

Plugin reaction:
- Fetches the certificate from Vault’s internal storage (not from Keyfactor).
- Returns PEM‑encoded certificate and metadata.

Outcome:
- Vault acts as a certificate cache for issued certs.

# 4. Event: A client lists certificates

vault list keyfactor/certs

Trigger:
Vault receives a list request.

Plugin reaction:
Enumerates stored certificate serial numbers.

Outcome:
Operator sees all certs issued through this plugin instance.

# 5. Event: A client revokes a certificate

vault write keyfactor/revoke/<serial>

Trigger:
Vault receives a revoke request.

Plugin reaction:
- Looks up certificate metadata (including Keyfactor Request ID).
- Sends a revocation request to Keyfactor.
- Updates Vault’s internal state.

Outcome:
- Keyfactor becomes the source of truth for revocation; Vault reflects the result.

# 6. Event: A client signs a CSR

vault write keyfactor/sign/<role> csr=<csr>

Trigger:
- Vault receives a CSR signing request.

Plugin reaction:
- Same pipeline as issuance, except CSR is provided by the caller.
- Keyfactor signs the CSR using the configured template + CA.

Outcome:
- Vault returns the signed certificate.

# 7. Event: A client requests CA or chain

vault read keyfactor/ca
vault read keyfactor/ca_chain

Trigger:
- Vault receives a read request for CA materials.

Plugin reaction:
- Fetches CA cert or chain from Keyfactor (or cached config).
- Returns it to the caller.

Outcome:
- Vault clients can bootstrap trust without direct access to Keyfactor.

#-----------------------------------------------------
Setup Flow
#-----------------------------------------------------

# 1. Event: Operator prepares Keyfactor for Vault

Trigger:
The operator creates a service identity in Keyfactor (Basic, OAuth, or TLS).

System reaction:
- Keyfactor generates the required authentication material:
username/password + domain
or client_id/client_secret + token endpoint
or certificate path
Keyfactor now has an identity that Vault can use to authenticate.

-------------------------

Trigger:
- The operator creates a certificate template in Keyfactor Command.
System reaction:
- Keyfactor imports the template and associates it with a CA.

-------------------------

Trigger:
- The operator enables CSR enrollment on the template.
System reaction:
- Keyfactor marks the template as eligible for API‑driven enrollment.

------------------------

Trigger:
- The operator assigns READ + ENROLL permissions to the service identity.

System reaction:
- Keyfactor authorizes this identity to request certificates using the template.

# 2. Event: Operator installs the plugin into Vault

---

Trigger:
The operator copies the plugin binary into Vault’s plugin directory.

System reaction:
Vault now has access to the executable but does not trust it yet.

---

Trigger:
The operator registers the plugin with a SHA‑256 checksum.

System reaction:

Vault:
- validates the checksum
- records the plugin in its plugin catalog
- associates the plugin name with the binary
The plugin is now known to Vault but not active.

---

Trigger:
The operator enables the secrets engine at a mount path (e.g., keyfactor/).

System reaction:

Vault:
- creates the mount
- loads the plugin on demand
- exposes the plugin’s API endpoints

The plugin is now ready to receive configuration events.

---

# 3. Event: Operator configures the plugin instance

Trigger:
The operator writes configuration values:
vault write keyfactor/config url=... ca=... template=...

System reaction:
- Vault forwards the config to the plugin.

The plugin:
- Validates the configuration structure.
- Attempts authentication to Keyfactor using the provided method.
- Verifies that the CA and template exist and are usable.
- Stores the configuration in Vault’s internal storage.
- If authentication fails, the plugin rejects the configuration event.

Trigger:
The operator reads back the configuration.

System reaction:
Vault returns the stored config, hiding sensitive fields unless show_hidden=true is provided.

---

# 4. Event: Operator defines issuance roles

Trigger:
The operator creates a role:
vault write keyfactor/roles/web allowed_domains=example.com allow_subdomains=true

System reaction:
Vault forwards the role definition to the plugin.

The plugin:
validates the domain rules
stores the role under the plugin’s role registry
This role becomes a domain filter for future issuance events.

Trigger:
The operator lists or reads roles.

System reaction:
Vault returns the role definitions stored by the plugin.

---

# 5. End State: Plugin is ready for issuance events
At this point:
- Keyfactor is prepared (template, permissions, service identity).
- Vault trusts and loads the plugin.
- The plugin is configured with Keyfactor connection details.
- Roles define domain boundaries for issuance.
- The system is now ready to process certificate issuance, signing, revocation, and CA retrieval events.
