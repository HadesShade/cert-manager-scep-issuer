# cert-manager SCEP External Issuer

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![Kubernetes](https://img.shields.io/badge/kubernetes-compatible-success.svg)
![cert-manager](https://img.shields.io/badge/cert--manager-v1.x-orange.svg)

A **Kubernetes external issuer for cert-manager that enables certificate
enrollment through SCEP (Simple Certificate Enrollment Protocol)**,
connecting Kubernetes workloads to enterprise Public Key Infrastructure
(PKI).

This controller supports two enrollment modes:

-   **Delegated mode** --- uses a persistent Registration Authority (RA)
    Agent identity to authenticate certificate requests.
-   **Direct mode** --- uses a temporary signing identity for SCEP
    endpoints that do not enforce signer-trust or challenge-password
    checks.

## Table of Contents

-   [Features](#features)
-   [Architecture and Enrollment Modes](#architecture-and-enrollment-modes)
-   [Installation](#installation)
-   [Usage Examples](#usage-examples)
    -   [Delegated Mode](#1-delegated-mode-with-ra-bootstrap)
    -   [Direct Mode](#2-direct-mode)
-   [Security Considerations](#security-considerations)
-   [Development and Contributing](#development-and-contributing)
-   [License](#license)

## Features

-   Integrates SCEP certificate enrollment with
    [cert-manager](https://cert-manager.io/).
-   Supports namespaced `Issuer` and cluster-scoped `ClusterIssuer`
    resources.
-   Supports delegated enrollment using a Registration Authority (RA)
    Agent certificate.
-   Supports direct enrollment for SCEP endpoints that do not require an
    established trusted signer or challenge-password authentication.
-   Distributed as an OCI Helm chart hosted on GitHub Container Registry
    (GHCR).

## Architecture and Enrollment Modes

`cert-manager` generates and signs the inner PKCS#10 Certificate Signing
Request (CSR) before handing it to the external issuer. This affects how
SCEP authentication can be handled: the issuer cannot change the signed
CSR attributes without invalidating its signature.

Choose the enrollment mode based on the authentication requirements of
your SCEP server.

| Capability | Delegated mode | Direct mode |
| :--- | :--- | :--- |
| **SCEP request signer** | Persistent RA Agent identity | Temporary self-signed identity per request |
| **Established signer trust** | Intended for endpoints that require a trusted signer | Not provided by the temporary identity |
| **`challengeSecretRef`** | Used for RA bootstrap | Not supported |
| **Intended endpoint** | SCEP servers requiring an established signer identity | Endpoints that do not enforce signer-trust or challenge-password checks |

### 1. Delegated Mode

**Intended for SCEP environments that require an established, trusted
Registration Authority (RA) identity.**

In delegated mode, the controller uses a bootstrap challenge password to
enroll an RA Agent certificate from the SCEP server. Once the RA
certificate is acquired, the controller uses that identity to
authenticate subsequent leaf certificate requests.

This avoids needing to inject a separate challenge password into every
leaf CSR, which the external issuer cannot modify after cert-manager has
signed it.

SCEP servers such as [OpenXPKI](https://www.openxpki.org/) and
[EJBCA](https://www.ejbca.org/) may be relevant for this mode, depending
on their configuration and compatibility with the issuer.

### 2. Direct Mode

**Intended for SCEP endpoints that do not enforce established signer
trust or challenge-password authentication.**

In direct mode, the controller wraps the cert-manager-generated leaf CSR
in a SCEP `PKIOperation` message and signs the request using a
temporary, self-signed identity generated for that request. SCEP
requests require a signing identity even when the receiving endpoint
does not enforce an established signer identity.

**Limitation:** Direct mode does **not** support `challengeSecretRef`. A
SCEP server that requires a `challengePassword` attribute inside the
original CSR or requires a trusted request signer is not suitable for
this mode. Since cert-manager has already signed the CSR, changing its
attributes would invalidate the signature.

## Installation

The controller is packaged as an OCI Helm chart hosted on GitHub
Container Registry (GHCR).

### Prerequisites

-   A Kubernetes cluster.
-   Helm 3.8.0 or later (for OCI registry support).
-   [cert-manager](https://cert-manager.io/docs/installation/) installed
    and running.
-   A reachable SCEP endpoint configured for the enrollment mode you
    intend to use.

### Install via Helm

Install chart version `0.1.0` from GHCR:

```bash
helm install scep-issuer \
  oci://ghcr.io/hadesshade/charts/scep-issuer \
  --version 0.1.0 \
  --namespace cert-manager
```

The Helm chart bundles the CRDs `issuers.scep.hshade.io` and
`clusterissuers.scep.hshade.io`, which are installed automatically.

## Usage Examples

The following examples use placeholder values. Replace the SCEP URL,
subject details, and challenge password with values appropriate for your
environment.

### 1. Delegated Mode (With RA Bootstrap)

#### Step 1: Create the bootstrap challenge Secret

Create a Kubernetes Secret containing the challenge password used to
bootstrap the RA Agent certificate:

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

Apply it:

```bash
kubectl apply -f scep-ra-challenge.yaml
```

#### Step 2: Create an Issuer

The following example uses `delegatedSignerConfiguration` to define the
RA Agent certificate identity.

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
  delegatedSignerConfiguration:
    commonName: "your.ra.cn"
    dnsNames:
      - "your.ra.alt.name"
    subject:
      organizations:
        - "Your Organization"
      countries:
        - "ID"
      organizationalUnits:
        - "Your OU"
```

If you already have an appropriate RA TLS Secret, configure
`delegatedSignerSecretName` instead, as supported by the issuer.

Apply the manifest:

```bash
kubectl apply -f issuer.yaml
```

#### Step 3: Request a certificate

Create a cert-manager `Certificate` referencing the external issuer:

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

Apply the manifest and check the certificate status:

```bash
kubectl apply -f certificate.yaml
kubectl get certificate my-app-cert -n default
kubectl describe certificate my-app-cert -n default
kubectl get secret my-app-cert-tls -n default
```

The controller handles RA bootstrap and subsequent leaf certificate
enrollment according to the delegated-mode configuration.

### 2. Direct Mode

Use direct mode only when the SCEP endpoint does not enforce established
signer trust or challenge-password authentication.

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
  # challengeSecretRef is not supported in Direct mode.
```

Apply the manifest:

```bash
kubectl apply -f direct-issuer.yaml
```

Create a cert-manager `Certificate` resource using the same structure as
the delegated example, but set `issuerRef.name` to `direct-scep-issuer`.

## Security Considerations

-   **TLS verification:** The examples set `insecureSkipVerify: true`.
    This disables server certificate verification and should not be used
    in production unless you have explicitly assessed and accepted the
    risk. Configure TLS verification appropriately for your environment.
-   **Bootstrap challenge:** Restrict access to the RA bootstrap Secret
    using Kubernetes RBAC. Do not commit real challenge passwords to
    source control.
-   **RA identity:** Protect the RA Agent private key and restrict
    access to the Secret that stores it.
-   **Direct mode:** Use only with SCEP endpoints whose authentication
    and approval policies are appropriate for requests signed by a
    temporary, untrusted identity.
-   **Issuance policy:** Ensure the SCEP server's approval and
    certificate issuance policies are appropriate for the certificates
    being requested.

## Development and Contributing

This project is built using [Kubebuilder](https://book.kubebuilder.io/).

### Building locally

Generate manifests and deepcopy code:

```bash
make manifests generate
```

Run tests:

```bash
make test
```

Run the controller locally using your current kubeconfig context:

```bash
make run
```

### Building and pushing images

```bash
make docker-build docker-push IMG=<your-registry>/scep-issuer:v0.1.0
```

Bug reports, suggestions, and contributions can be submitted through the
[GitHub repository](https://github.com/HadesShade/cert-manager-scep-issuer).

## License

Copyright © 2026 Kevin Tim.

Licensed under the Apache License, Version 2.0. You may obtain a copy of
the License at:

https://www.apache.org/licenses/LICENSE-2.0
