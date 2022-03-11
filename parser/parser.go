// Package parser provides functions to read raw YAML input and returns the Istio configuration object.
package parser

import (
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"path/filepath"

	"reflect"
	"strings"

	"github.com/ghodss/yaml"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

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

	authzNegativeMatchInAllow = errors.New("authorization policy: found negative matches in allow policy")
	authzPositiveDeny         = errors.New("authorization policy: found positive matches in deny policy")

	destinationRuleTlsNotVerify = errors.New("destination rule: either caCertificates or subjectAltNames is not set.")
)

// Report contains the scanning report.
type Report struct {
	SecurityPolicyCount   int
	NetworkingPolicyCount int
	PolicyIssues          []error
	Vunerabilities        []string
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
		typedSpec := specField.Addr().Interface()

		configs = append(configs, &istioConfig.Config{
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
		})
	}
	return configs, nil
}

func CheckAll(configs []*istioConfig.Config) []error {
	out := []error{}
	for _, c := range configs {
		switch c.GroupVersionKind {
		case istiogvk.AuthorizationPolicy:
			authz, ok := c.Spec.(*istiosec.AuthorizationPolicy)
			if !ok {
				log.Errorf("unable to convert to istio authz policy: %v\n%v", ok, c.Spec)
				continue
			}
			if err := chekcAuthorizationPolicy(authz); err != nil {
				out = append(out, err)
			}
		case istiogvk.DestinationRule:
			dr, ok := c.Spec.(*networkingv1.DestinationRule)
			if !ok {
				log.Errorf("unable to convert to istio authz policy: %v\n%v", ok, c.Spec)
				continue
			}
			if err := checkDestinationRule(dr); err != nil {
				out = append(out, err)
			}
		}
	}
	return out
}

// CheckFileSystem checks configuration stored on file system.
func CheckFileSystem(dir string) []error {
	out := []error{}
	err := filepath.WalkDir(dir, func(path string, dir fs.DirEntry, _ error) error {
		log.Infof("Checking config: %v", path)
		if dir.IsDir() {
			return nil
		}
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		configs, err := decodeConfigYAML(string(b))
		if err != nil {
			return fmt.Errorf("failed to decode config: %v", err)
		}
		errs := CheckAll(configs)
		if len(errs) != 0 {
			out = append(out, errs...)
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

func chekcAuthorizationPolicy(authz *istiosec.AuthorizationPolicy) error {
	if authz == nil {
		return nil
	}
	if authz.Action == istiosec.AuthorizationPolicy_ALLOW {
		for _, r := range authz.Rules {
			for _, f := range r.From {
				if hasNegativeMatchInFrom(f) {
					return authzNegativeMatchInAllow
				}
			}
			for _, t := range r.To {
				if hasNegativMatchInTo(t) {
					return authzNegativeMatchInAllow
				}
			}
			for _, cond := range r.When {
				if len(cond.NotValues) != 0 {
					return authzNegativeMatchInAllow
				}
			}
		}
	}
	if authz.Action == istiosec.AuthorizationPolicy_DENY {
		for _, r := range authz.Rules {
			for _, f := range r.From {
				if hasPositiveMatchInFrom(f) {
					return authzPositiveDeny
				}
			}
			for _, t := range r.To {
				if hasPositiveMatchInTo(t) {
					return authzPositiveDeny
				}
			}
			for _, cond := range r.When {
				if len(cond.Values) != 0 {
					return authzNegativeMatchInAllow
				}
			}
		}
	}
	return nil
}

func checkTlsSettings(tls *networkingv1.ClientTLSSettings) error {
	if tls == nil {
		return nil
	}
	// TODO(jianfeih): here.
	return nil
}

func checkDestinationRule(dr *networkingv1.DestinationRule) error {
	if dr == nil {
		return nil
	}
	if err := checkTlsSettings(dr.GetTrafficPolicy().GetTls()); err != nil {
		return destinationRuleTlsNotVerify
	}
	for _, ps := range dr.GetTrafficPolicy().PortLevelSettings {
		if err := checkTlsSettings(ps.GetTls()); err != nil {
			return destinationRuleTlsNotVerify
		}
	}
	for _, ss := range dr.GetSubsets() {
		if err := checkTlsSettings(ss.GetTrafficPolicy().GetTls()); err != nil {
			return destinationRuleTlsNotVerify
		}
	}
	return nil
}
