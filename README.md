# Istio Security Analyzer

This is a tool to analyze Istio security. Roughly the tool covers two aspects

1. Ensure configuration adhering to [Istio Security Best Practice](https://istio.io/latest/docs/ops/best-practices/security).
1. Checks the running Istio version to see if has any known CVE issues.

## Get Started

### Install Istio

Install Istio 1.12.1. We choose this specific version so that we can demo how CVE detection works.

```sh
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=1.12.1 sh
pushd istio-1.12.1
./bin/istioctl install --set profile=demo -y
```

Apply some sample configuration. To illustrate, we provide some sample problematic configuration.

```sh
kubectl apply -f ./pkg/parser/testdata/
```

### Check Basics

Now let's just run the tool without any configuration.

```sh
scanner
```

You will see some report as below. In this report, we identified a few issues.

- Reminds you that you can harden your Istio deployment via using hardened distroless image.
- Reports security vunerabilities found for Istio 1.12.1. For example, [Istio-security-2022-004](https://istio.io/latest/news/security/istio-security-2022-004/) means unauthenticated request to Istiod control plane can make
Istiod crash by exhausting its memory.
- Config Warnings section reminds you that the cluster does not have k8s RBAC to
[control](https://istio.io/latest/docs/ops/best-practices/security/#restrict-gateway-creation-privileges)
who can create Istio gateway resource.

```text
==========================================
    Istio Security Scanning Report

Control Plane Version
- 1.12.1

Distroless Warning
- pod istio-egressgateway-687f4db598-rn5hs can use a distroless image for better security, current docker.io/istio/proxyv2:1.12.1

CVE Report
- ISTIO-SECURITY-2022-004
- ISTIO-SECURITY-2022-003
- ISTIO-SECURITY-2022-001
- ISTIO-SECURITY-2022-002

Config Warnings
- failed to find cluster role and role bindings to control istio gateway creation
```

### Config Scanning

TODO(incfly): more on the config issue pattern detection.
