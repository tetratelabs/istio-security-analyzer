# Istio Security Analyzer

This is a tool to analyze Istio security. Roughly the tool covers two aspects

1. Ensure configuration adhering to [Istio Security Best Practice](https://istio.io/latest/docs/ops/best-practices/security).
1. Checks the running Istio version to see if has any known CVE issues.

## Get Started

Install Istio.

```sh
istioctl install --set profile=demo
```

Apply some sample configuration. To illustrate, we provide some sample problematic configuration.

```sh
kubectl apply -f ./pkg/parser/testdata/
```

Run the tool.

```sh
make build && ./out/scanner
```

TODO(incfly): Change to default istio (better to be certain version), run;
Explain issues, apply config, and then run again.
