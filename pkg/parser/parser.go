// Package parser provides functions to read raw YAML input and returns the Istio configuration object.
package parser

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"

	"reflect"
	"strings"

	"github.com/ghodss/yaml"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	networkingv1alpha3 "istio.io/api/networking/v1alpha3"
	networkingv1 "istio.io/api/networking/v1beta1"
	istiosec "istio.io/api/security/v1beta1"

	istioscheme "istio.io/client-go/pkg/clientset/versioned/scheme"
	istioConfig "istio.io/istio/pkg/config"
	istiogvk "istio.io/istio/pkg/config/schema/gvk"
	"istio.io/pkg/log"
)

var (
	schemeBuilder = runtime.NewSchemeBuilder(
		istioscheme.AddToScheme,
		scheme.AddToScheme,
	)
)

const (
	authzNegativeMatchInAllow   = "authorization policy: found negative matches in allow policy"
	authzPositiveDeny           = "authorization policy: found positive matches in deny policy"
	destinationRuleTlsNotVerify = "destination rule: either caCertificates or subjectAltNames is not set."
)

// Report contains the scanning report.
type Report struct {
	SecurityPolicyCount   int
	NetworkingPolicyCount int
	PolicyIssues          []error
	Vunerabilities        []string
}

func reportError(c *istioConfig.Config, message string) error {
	return fmt.Errorf("%v %v/%v: %v", c.GroupVersionKind, c.Namespace, c.Name, message)
}

// Parse reads the given configuration file.
func ParseFile(filename string) (string, error) {
	return "", nil
}

// Parse reads all files specified in the input directory.
func ParseDir(dir string) (string, error) {
	return "", nil
}

func ReadConfigObjects(files ...string) ([]*istioConfig.Config, error) {
	configObjects := make([]*istioConfig.Config, 0)
	for _, inputTmpl := range files {
		yamlBytes, err := ioutil.ReadFile("testdata/" + inputTmpl)
		if err != nil {
			return nil, fmt.Errorf("unable to read file %s: %w", inputTmpl, err)
		}
		yamlStr := string(yamlBytes)
		kubeYaml := yamlStr
		cfgs, err := decodeConfigYAML(kubeYaml)
		if err != nil {
			return nil, fmt.Errorf("unable to decode kubernetes configs in file %s: %w", inputTmpl, err)
		}
		for _, cfg := range cfgs {
			cobjCopy := cfg.DeepCopy()
			configObjects = append(configObjects, &cobjCopy)
		}
	}
	return configObjects, nil
}

func getCombinedScheme() (*runtime.Scheme, error) {
	combinedScheme := runtime.NewScheme()
	err := schemeBuilder.AddToScheme(combinedScheme)
	if err != nil {
		return nil, fmt.Errorf("failed to build combined scheme of Istio and builtin K8s: %v", err)
	}
	return combinedScheme, nil
}

func decodeConfigYAML(rawYAML string) ([]*istioConfig.Config, error) {
	configs := make([]*istioConfig.Config, 0)
	yamls := strings.Split(rawYAML, "\n---")
	combinedScheme, err := getCombinedScheme()
	if err != nil {
		return nil, err
	}
	for _, y := range yamls {
		if strings.TrimSpace(y) == "" {
			continue
		}
		var obj map[string]interface{}
		err := yaml.Unmarshal([]byte(y), &obj)
		if err != nil {
			return nil, err
		}
		un := unstructured.Unstructured{Object: obj}
		gvk := un.GroupVersionKind()
		name, namespace := un.GetName(), un.GetNamespace()
		labels, annotations := un.GetLabels(), un.GetAnnotations()
		kobj, err := combinedScheme.New(gvk)
		if err != nil {
			return nil, err
		}
		err = combinedScheme.Convert(&un, kobj, nil)
		if err != nil {
			return nil, err
		}

		objType := reflect.TypeOf(kobj)
		if objType.Kind() != reflect.Ptr {
			return nil, fmt.Errorf("expected pointer type, but got %s", objType.Kind().String())
		}
		kobjVal := reflect.ValueOf(kobj).Elem()
		specField := kobjVal.FieldByName("Spec")
		if !specField.IsValid() {
			return nil, fmt.Errorf("not find Spec field in the YALM")
		}
		typedSpec := specField.Addr().Interface()

		cfg := &istioConfig.Config{
			Meta: istioConfig.Meta{
				GroupVersionKind: istioConfig.GroupVersionKind{
					Group:   gvk.Group,
					Version: gvk.Version,
					Kind:    gvk.Kind,
				},
				Name:        name,
				Namespace:   namespace,
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: typedSpec,
		}
		if changed := maybeConverToV1Alpha3(cfg); changed {
			log.Debugf("config %v-%v/%v transformed to v1alpha3", cfg.GroupVersionKind.String(), cfg.Namespace, cfg.Name)
		}
		configs = append(configs, cfg)
	}
	return configs, nil
}

// Returns true if the input config does get converted to v1alpha3 version.
// We tentatively convert some resources to v1alpha3 version. This free the analyzing logic to
// deal with two versions together. Istioctl analyzer does not handle this well either.
// Instrument this line, showing the `parseContent` returning empty list when the input CR on filesystem
// are networking v1beta1.
// https://github.com/istio/istio/blob/aeb20fac89944f8961c0276b3d70e98fd04f30bb/galley/pkg/config/source/kube/inmemory/kubesource.go#L151
// We only have to deal with in the CLI mode since in k8s case, stored version of Istio API isall
// v1alpha3 in APIServer natively already.
func maybeConverToV1Alpha3(input *istioConfig.Config) bool {
	gvk := input.GroupVersionKind
	log.Debugf("converting %v", input.Name)
	// Only destination rule for now.
	if gvkEqualsIgnoringVersion(gvk, istiogvk.DestinationRule) {
		input.GroupVersionKind = istiogvk.DestinationRule
		drv1, ok := input.Spec.(*networkingv1.DestinationRule)
		if !ok {
			log.Errorf("failed to convert to destination rule, do nothing")
			return false
		}
		drJSON, err := drv1.MarshalJSON()
		if err != nil {
			log.Errorf("failed to convert to JSON")
			return false
		}
		var drAlpha networkingv1alpha3.DestinationRule
		if err := drAlpha.UnmarshalJSON(drJSON); err != nil {
			log.Errorf("failed to unmarshal from v1 json bytes: %v", err)
			return false
		}
		input.Spec = &drAlpha
		return true
	}
	return false
}

func gvkEqualsIgnoringVersion(input, target istioConfig.GroupVersionKind) bool {
	input.Version = ""
	target.Version = ""
	return input == target
}

func CheckAll(configs []*istioConfig.Config) []error {
	out := []error{}
	for _, c := range configs {
		if gvkEqualsIgnoringVersion(c.GroupVersionKind, istiogvk.AuthorizationPolicy) {
			if err := checkAuthorizationPolicy(c); err != nil {
				out = append(out, err)
			}
		}
		if gvkEqualsIgnoringVersion(c.GroupVersionKind, istiogvk.DestinationRule) {
			if err := checkDestinationRule(c); err != nil {
				out = append(out, err)
			}
		}
		if gvkEqualsIgnoringVersion(c.GroupVersionKind, istiogvk.Gateway) {
			if err := checkGateway(c); err != nil {
				out = append(out, err)
			}
		}
	}
	return out
}

// CheckFileSystem checks configuration stored on file system.
func CheckFileSystem(dir string) []error {
	out := []error{}
	// first check the entry point is a valid path.
	if _, err := os.Stat(dir); err != nil {
		return []error{fmt.Errorf("%v is not a valid path: %v", dir, err)}
	}
	err := filepath.WalkDir(dir, func(path string, dir fs.DirEntry, _ error) error {
		log.Debugf("Checking file: %v", path)
		if dir.IsDir() {
			return nil
		}
		b, err := ioutil.ReadFile(path)
		if err != nil {
			log.Debugf("failed to read the file: %v", err)
			return nil
		}
		configs, err := decodeConfigYAML(string(b))
		if err != nil {
			log.Debugf("failed to read the file: %v", err)
			return nil
		}
		log.Debugf("Checking Istio config file: %v", path)
		errs := CheckAll(configs)
		for _, e := range errs {
			if e != nil {
				out = append(out, e)
			}
		}
		return nil
	})
	if err != nil {
		log.Debugf("Skip, failed to iterate the directory %v: %v", dir, err)
	}
	return out
}

func hasNegativeMatchInFrom(from *istiosec.Rule_From) bool {
	if from == nil {
		return false
	}
	return len(from.Source.NotNamespaces) != 0 || len(from.Source.NotPrincipals) != 0 ||
		len(from.Source.NotIpBlocks) != 0 || len(from.Source.NotPrincipals) != 0 ||
		len(from.Source.NotRemoteIpBlocks) != 0 || len(from.Source.NotRequestPrincipals) != 0
}

func hasNegativMatchInTo(to *istiosec.Rule_To) bool {
	if to == nil {
		return false
	}
	return len(to.Operation.NotHosts) != 0 || len(to.Operation.NotMethods) != 0 ||
		len(to.Operation.NotPaths) != 0 || len(to.Operation.NotPorts) != 0
}

func hasPositiveMatchInFrom(from *istiosec.Rule_From) bool {
	if from == nil {
		return false
	}
	return len(from.Source.Namespaces) != 0 || len(from.Source.Principals) != 0 ||
		len(from.Source.IpBlocks) != 0 || len(from.Source.Principals) != 0 ||
		len(from.Source.RemoteIpBlocks) != 0 || len(from.Source.RequestPrincipals) != 0
}

func hasPositiveMatchInTo(to *istiosec.Rule_To) bool {
	if to == nil {
		return false
	}
	return len(to.Operation.Hosts) != 0 || len(to.Operation.Methods) != 0 ||
		len(to.Operation.Paths) != 0 || len(to.Operation.Ports) != 0
}

func checkAuthorizationPolicy(c *istioConfig.Config) error {
	if c == nil {
		return nil
	}
	log.Debugf("Checking authorization policy %v/%v", c.Namespace, c.Name)
	authz, ok := c.Spec.(*istiosec.AuthorizationPolicy)
	if !ok {
		log.Errorf("unable to convert to istio authz policy: %v\n%v", ok, c.Spec)
		return nil
	}
	if authz.Action == istiosec.AuthorizationPolicy_ALLOW {
		for _, r := range authz.Rules {
			for _, f := range r.From {
				if hasNegativeMatchInFrom(f) {
					return reportError(c, authzNegativeMatchInAllow)
				}
			}
			for _, t := range r.To {
				if hasNegativMatchInTo(t) {
					return reportError(c, authzNegativeMatchInAllow)
				}
			}
			for _, cond := range r.When {
				if len(cond.NotValues) != 0 {
					return reportError(c, authzNegativeMatchInAllow)
				}
			}
		}
	}
	if authz.Action == istiosec.AuthorizationPolicy_DENY {
		for _, r := range authz.Rules {
			for _, f := range r.From {
				if hasPositiveMatchInFrom(f) {
					return reportError(c, authzPositiveDeny)
				}
			}
			for _, t := range r.To {
				if hasPositiveMatchInTo(t) {
					return reportError(c, authzPositiveDeny)
				}
			}
			for _, cond := range r.When {
				if len(cond.Values) != 0 {
					return reportError(c, authzPositiveDeny)
				}
			}
		}
	}
	return nil
}

// TODO(incfly): the correct logic, to be verified in experiment though is
// - if VERIFY_CERTIFICATE_AT_CLIENT is false and destination rule does not have ca cert specified
//   reports warnings.
// - if not so, but the sub alt name is empty, report warning as well.
// For now we only check the config statically.
func hasVerificationIssue(tls *networkingv1alpha3.ClientTLSSettings) bool {
	if tls == nil {
		return false
	}
	mode := tls.GetMode()
	if mode == networkingv1alpha3.ClientTLSSettings_DISABLE || mode == networkingv1alpha3.ClientTLSSettings_ISTIO_MUTUAL {
		return false
	}
	return len(tls.SubjectAltNames) == 0
}

func checkDestinationRule(c *istioConfig.Config) error {
	if c == nil {
		return nil
	}
	dr, ok := c.Spec.(*networkingv1alpha3.DestinationRule)
	if !ok {
		log.Errorf("unable to convert to istio destination rule: ok: %v\n%v", ok, c.Spec)
		return nil
	}
	if hasVerificationIssue(dr.GetTrafficPolicy().GetTls()) {
		return reportError(c, destinationRuleTlsNotVerify)
	}
	for _, ps := range dr.GetTrafficPolicy().GetPortLevelSettings() {
		if hasVerificationIssue(ps.GetTls()) {
			return reportError(c, destinationRuleTlsNotVerify)
		}
	}
	for _, ss := range dr.GetSubsets() {
		if hasVerificationIssue(ss.GetTrafficPolicy().GetTls()) {
			return reportError(c, destinationRuleTlsNotVerify)
		}
	}
	return nil
}

func checkGateway(c *istioConfig.Config) error {
	if c == nil {
		return nil
	}
	gw, ok := c.Spec.(*networkingv1alpha3.Gateway)
	if !ok {
		log.Errorf("unable to convert to istio destination rule: ok: %v\n%v", ok, c.Spec)
		return nil
	}
	for _, srv := range gw.Servers {
		for _, host := range srv.Hosts {
			if host == "*" {
				return reportError(c, `host "*" is overly broad, consider to assign a`+
					`specific domain name such as foo.example.com`)
			}
		}
	}
	return nil
}
