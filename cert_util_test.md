## 📘 **Use Case: Local CSR Generation From Private Key**

### **Goal**
Verify that the backend can locally generate a valid CSR (Certificate Signing Request) and corresponding private key without interacting with external systems. This ensures that Vault can produce standards‑compliant CSRs before submitting them to Keyfactor or any other CA.

### **Primary Actor**
Vault Keyfactor backend (internal CSR generator)

### **Trigger**
A client or internal workflow requests a new CSR for a certificate issuance operation.

### **Preconditions**
- The backend is instantiated.
- No external configuration or network connectivity is required.
- The caller provides:
  - A Common Name (CN)
  - IP Subject Alternative Names (IP SANs)
  - DNS Subject Alternative Names (DNS SANs)

### **Main Success Scenario**
1. The backend generates a new RSA private key.
2. The backend constructs a CSR containing:
   - The provided Common Name
   - The provided IP SANs
   - The provided DNS SANs
3. The CSR is encoded in PEM format.
4. The private key is returned in PKCS#1 format.
5. The test parses the CSR to validate:
   - The Common Name matches the input
   - All IP SANs are present and correctly encoded
   - All DNS SANs are present and correctly encoded

### **Expected Outputs**
- `csr string` — PEM‑encoded CSR
- `privKey []byte` — PKCS#1‑encoded RSA private key
- No error during CSR parsing
- CSR fields match the input parameters

### **Postconditions**
- A valid CSR and private key pair are produced.
- No external systems are contacted.
- The CSR is ready for submission to Keyfactor or any other CA.

### **Test Purpose**
This test ensures that the CSR generation logic:

- Produces syntactically valid CSRs
- Correctly embeds SANs
- Correctly encodes the subject
- Generates a usable private key
- Behaves deterministically for given inputs

This validates the foundation required for the full certificate enrollment workflow.

---
