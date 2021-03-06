package yaml

import (
	"fmt"
	"github.com/armory/go-yaml-tools/pkg/secrets"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	yaml "gopkg.in/yaml.v2"
)

func check(t *testing.T, e error) {
	if e != nil {
		t.Errorf("error when testing: %s", e)
	}
}

func TestSubValues(t *testing.T) {
	m := map[string]interface{}{
		"mock": map[string]interface{}{
			"somekey": "${mock.flat.otherkey.value}",
			"flat": map[string]interface{}{
				"otherkey": map[string]interface{}{
					"value": "mockReplaceValue",
				},
			},
		},
	}

	subValues(m, m, nil)
	testValue := m["mock"].(map[string]interface{})["somekey"]
	assert.Equal(t, "mockReplaceValue", testValue)
}

func TestResolveSubs(t *testing.T) {
	m := map[string]interface{}{
		"mock": map[string]interface{}{
			"flat": map[string]interface{}{
				"otherkey": map[string]interface{}{
					"value": "mockValue",
				},
			},
		},
	}
	str := resolveSubs(m, "mock.flat.otherkey.value", nil)
	assert.Equal(t, "mockValue", str)
}

func readTestFixtures(t *testing.T, fileName string) map[interface{}]interface{} {
	wd, _ := os.Getwd()
	spinnakerYml := fmt.Sprintf("%s/../../test/%s", wd, fileName)
	f, err := os.Open(spinnakerYml)
	check(t, err)
	s, err := ioutil.ReadAll(f)
	check(t, err)

	any := map[interface{}]interface{}{}
	err = yaml.Unmarshal(s, &any)
	check(t, err)

	return any
}

func TestResolver(t *testing.T) {

	fileNames := []string{
		"spinnaker.yml",
		"spinnaker-armory.yml",
		"spinnaker-local.yml",
	}

	ymlMaps := []map[interface{}]interface{}{}
	for _, f := range fileNames {
		ymlMaps = append(ymlMaps, readTestFixtures(t, f))
	}
	envKeyPairs := map[string]string{
		"SPINNAKER_AWS_ENABLED": "true",
		"DEFAULT_DNS_NAME":      "mockdns.com",
		"REDIS_HOST":            "redishost.com",
	}

	resolved, err := Resolve(ymlMaps, envKeyPairs)
	if err != nil {
		t.Error(err)
	}
	//simple replace
	host := resolved["services"].(map[string]interface{})["rosco"].(map[string]interface{})["host"]
	assert.Equal(t, "mockdns.com", host)

	providers := resolved["providers"].(map[string]interface{})
	services := resolved["services"].(map[string]interface{})
	google := providers["google"].(map[string]interface{})
	googleEnabled := google["enabled"]
	assert.Equal(t, "false", googleEnabled)

	//default when no ENV var is present
	defaultRegion := providers["aws"].(map[string]interface{})["defaultRegion"]
	assert.Equal(t, "us-east-1", defaultRegion)

	//more complex substitution with urls
	fiatURL := services["fiat"].(map[string]interface{})["baseUrl"]
	assert.Equal(t, "http://mockdns.com:7003", fiatURL)

	//secret resolve
	echoSlackApiKey := services["echo"].(map[string]interface{})["slackApiKey"]
	assert.Equal(t, "mynotsosecretstring", echoSlackApiKey)
	terraformerProfilesSSHKey := services["terraformer"].(map[string]interface{})["profiles"].([]interface{})[0].(map[string]interface{})["variables"].([]interface{})[0].(map[string]interface{})["options"].(map[string]interface{})["sshKeyContents"]
	assert.Equal(t, "mynotsosecretsshstring", terraformerProfilesSSHKey)

	//empty url
	project := google["primaryCredentials"].(map[string]interface{})["project"]
	assert.Equal(t, "", project)
}

func TestResolverCollections(t *testing.T) {

	fileNames := []string{
		"collections.yml",
	}

	ymlMaps := []map[interface{}]interface{}{}
	for _, f := range fileNames {
		ymlMaps = append(ymlMaps, readTestFixtures(t, f))
	}
	envKeyPairs := map[string]string{
		"SPINNAKER_AWS_ENABLED": "true",
		"DEFAULT_DNS_NAME":      "mockdns.com",
		"REDIS_HOST":            "redishost.com",
	}

	resolved, err := Resolve(ymlMaps, envKeyPairs)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "http://localhost:8080", resolved["baseUrl"])
	assert.Equal(t, []interface{}{map[string]interface{}{"multi_one_one": "one-one", "multi_one_two": "one-two"}, map[string]interface{}{"multi_two_one": "two-one", "multi_two_two": "two-two"}}, resolved["multiValCol"])
	assert.Equal(t, []interface{}{map[string]interface{}{"multi_one_one": "one-one", "multi_one_two": "one-two"}, map[string]interface{}{"multi_two_one": "two-one", "multi_two_two": "two-two"}}, resolved["multiValColAgain"])
	assert.Equal(t, []interface{}{"one", "two", "three"}, resolved["col"])
}

var userpassYaml = `
    secrets:
      vault:
        enabled: true
        url: https://vault.com
        username: name
        password: pw
        userAuthPath: userpass
        authMethod: USERPASS
`
var kubernetesYaml = `
    secrets:
      vault:
        enabled: true
        url: https://vault.com
        namespace: ent-namespace
        path: kubernetes
        role: my-role
        authMethod: KUBERNETES
`
var tokenYaml = `
    secrets:
      vault:
        enabled: true
        url: https://vault.com
        authMethod: TOKEN
`
var disabledYaml = `
    secrets:
      vault:
        enabled: false
        url: https://vault.com
        authMethod: TOKEN
`
func Test_DecodeVaultConfig(t *testing.T) {
	cases := map[string]struct {
		yaml string
		expected *secrets.VaultConfig
	}{
		"happy path - userpass auth": {
			yaml: userpassYaml,
			expected: &secrets.VaultConfig{
				Enabled:      true,
				Url:          "https://vault.com",
				AuthMethod:   "USERPASS",
				Username:     "name",
				Password:     "pw",
				UserAuthPath: "userpass",
			},
		},
		"happy path - kubernetes auth with namespace": {
			yaml: kubernetesYaml,
			expected: &secrets.VaultConfig{
				Enabled:      true,
				Url:          "https://vault.com",
				AuthMethod:   "KUBERNETES",
				Path: "kubernetes",
				Role: "my-role",
				Namespace: "ent-namespace",
			},
		},
		"happy path - token auth": {
			yaml: tokenYaml,
			expected: &secrets.VaultConfig{
				Enabled:      true,
				Url:          "https://vault.com",
				AuthMethod:   "TOKEN",
			},
		},
		"happy path - disabled": {
			yaml: disabledYaml,
			expected: &secrets.VaultConfig{
				Enabled:      false,
				Url:          "https://vault.com",
				AuthMethod:   "TOKEN",
			},
		},
	}
	for testName, c := range cases {
		t.Run(testName, func(t *testing.T) {

			any := map[interface{}]interface{}{}
			err := yaml.Unmarshal([]byte(c.yaml), &any)
			assert.Nil(t, err)

			config := extractVaultConfig(any)
			assert.EqualValues(t, c.expected, config)
		})
	}
}
