# cert-manager SCEP External Issuer

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![Kubernetes](https://img.shields.io/badge/kubernetes-compatible-success.svg)
![cert-manager](https://img.shields.io/badge/cert--manager-v1.x-orange.svg)

A Kubernetes [cert-manager](https://cert-manager.io/) external issuer controller that enables certificate enrollment via the Simple Certificate Enrollment Protocol (SCEP). 

This project bridges the gap between modern cloud-native Kubernetes workloads and enterprise Public Key Infrastructure (PKI) systems, supporting both **Delegated (RA Agent)** and **Direct** enrollment modes.

---

## 🏗️ Architecture & Enrollment Modes

Because `cert-manager` inherently generates and signs the inner PKCS#10 CSR before handing it to external controllers, this issuer implements two distinct architectures to handle SCEP's `challengePassword` requirements.

### 1. Delegated Mode (Recommended / Enterprise Standard)
**Best for:** Strict RFC-compliant CAs like **OpenXPKI** and **MicroMDM**.

In Delegated Mode, the controller uses a bootstrap secret challenge to enroll a **Registration Authority (RA) Agent** certificate from the SCEP server. Once the RA certificate is acquired, the controller uses it to authenticate all subsequent leaf certificate requests. 
* **Advantage:** Completely bypasses the need for individual leaf challenge passwords, overcoming the cryptographic limitation of injecting attributes into pre-signed cert-manager CSRs.

### 2. Direct Mode
**Best for:** CAs configured for auto-approval (no challenge passwords required).

In Direct Mode, the controller submits the cert-manager generated leaf CSR directly to the SCEP endpoint. 
* **Limitation:** Direct Mode does **not** support challenge passwords (`challengeSecretRef`). Strict SCEP servers require the `challengePassword` embedded inside the mathematically signed inner CSR. Because cert-manager isolates private keys, external controllers cannot modify the inner CSR attributes without invalidating its signature. Direct Mode is strictly reserved for auto-approving endpoints.

---

## 🚀 Installation

The controller is packaged as an OCI Helm chart and hosted on GitHub Container Registry (GHCR).

### Prerequisites
* Kubernetes cluster
* Helm 3.8.0+ (for OCI registry support)
* [cert-manager](https://cert-manager.io/docs/installation/) installed and running

### Install via Helm

Install the chart directly from the GHCR OCI registry:

```bash
helm install scep-issuer oci://ghcr.io/hadesshade/charts/scep-issuer \
  --version 0.1.0 \
  --namespace cert-manager
```

*Note: The CRDs (`issuers.scep.hshade.io`, `clusterissuers.scep.hshade.io`) are bundled within the Helm chart and will be installed automatically.*

---

## 📖 Usage Examples

### Example 1: Delegated Mode (With RA Bootstrap)

First, create a secret containing the bootstrap challenge password for your RA Agent:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: scep-ra-challenge
  namespace: default
type: Opaque
stringData:
  password: "YourSuperSecretChallenge"
```

Next, create the `Issuer`:

```yaml
apiVersion: scep.hshade.io/v1alpha1
kind: Issuer
metadata:
  name: delegated-scep-issuer
  namespace: default
spec:
  url: http://your-scep-server.local/scep
  enrollmentMode: Delegated
  insecureSkipVerify: true
  challengeSecretRef:
    name: scep-ra-challenge
    key: password
```

Finally, request a certificate. The controller will automatically handle the RA bootstrap and sign the leaf:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-app-cert
  namespace: default
spec:
  secretName: my-app-cert-tls
  issuerRef:
    group: scep.hshade.io
    kind: Issuer
    name: delegated-scep-issuer
  dnsNames:
    - my-app.local
```

### Example 2: Direct Mode (Auto-Approving Endpoints)

Direct Mode submits requests directly to the SCEP server without challenge authentication.

```yaml
apiVersion: scep.hshade.io/v1alpha1
kind: Issuer
metadata:
  name: direct-scep-issuer
  namespace: default
spec:
  url: http://your-scep-server.local/scep
  enrollmentMode: Direct
  insecureSkipVerify: true
  # Note: challengeSecretRef is NOT supported in Direct mode.
```

---

## 🛠️ Development & Contributing

This project is built using [Kubebuilder](https://book.kubebuilder.io/). 

### Building locally
```bash
# Generate manifests and deepcopy code
make manifests generate

# Run tests
make test

# Run the controller locally against your current kubeconfig context
make run
```

### Building and Pushing Images
```bash
make docker-build docker-push IMG=ghcr.io/hadesshade/cert-manager-scep-issuer:latest
```

## 📜 License

Copyright © 2026 hadesshade.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0