package secrets

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"io/ioutil"
	"os"
	"strings"
)

type VaultConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Url        string `json:"url" yaml:"url"`
	AuthMethod string `json:"authMethod" yaml:"authMethod"`
	Role       string `json:"role" yaml:"role"`
	Path       string `json:"path" yaml:"path"`
	Token      string
}

type VaultSecret struct {
	engine        string
	path          string
	key           string
	base64Encoded string
}

type VaultDecrypter struct {
	encryptedSecret string
	vaultConfig     VaultConfig
	isKV2           map[string]struct{}
}

func NewVaultDecrypter(encryptedSecret string) *VaultDecrypter {
	return &VaultDecrypter{encryptedSecret, VaultConfig{}, map[string]struct{}{}}
}

func getVaultDecrypter(encryptedSecret string) Decrypter {
	decrypter := NewVaultDecrypter(encryptedSecret)
	decrypter.vaultConfig = Registry.VaultConfig
	return decrypter
}

func (v *VaultDecrypter) Decrypt() (string, error) {
	if err := v.ValidateVaultConfig(); err != nil {
		return "", fmt.Errorf("vault configuration error - %s", err)
	}

	vaultSecret, err := ParseVaultEncryptedSecret(v.encryptedSecret)
	if err != nil {
		return "", fmt.Errorf("error parsing vault secret syntax - %s", err)
	}

	if v.vaultConfig.Token == "" {
		token, err := v.FetchVaultToken()
		if err != nil {
			return "", fmt.Errorf("error fetching vault token - %s", err)
		}
		v.vaultConfig.Token = token
	}

	secret, err := v.FetchSecret(vaultSecret)
	if err != nil {
		// get new token and retry in case our saved token is no longer valid
		return v.RetryFetchSecret(vaultSecret)
	}
	return secret, nil
}

func (v *VaultDecrypter) ValidateVaultConfig() error {
	if (VaultConfig{}) == v.vaultConfig {
		return fmt.Errorf("vault secrets not configured in service profile yaml")
	}
	if v.vaultConfig.Enabled == false {
		return fmt.Errorf("vault secrets disabled")
	}
	if v.vaultConfig.AuthMethod == "" {
		return fmt.Errorf("auth method required")
	}
	if v.vaultConfig.Url == "" {
		return fmt.Errorf("vault url required")
	}
	return nil
}

func ParseVaultEncryptedSecret(encryptedSecret string) (VaultSecret, error) {
	var vaultSecret VaultSecret
	configs := strings.Split(encryptedSecret, "!")
	if len(configs) < 2 {
		return VaultSecret{}, fmt.Errorf("illegal format: %q", encryptedSecret)
	}
	for _, element := range configs {
		kv := strings.Split(element, ":")
		if len(kv) < 2 {
			return VaultSecret{}, fmt.Errorf("illegal format for key-value pair in %q: %s",
				encryptedSecret, element)
		}
		switch kv[0] {
		case "encrypted":
			// do nothing
		case "e":
			vaultSecret.engine = kv[1]
		case "n":
			vaultSecret.path = kv[1]
		case "k":
			vaultSecret.key = kv[1]
		case "b":
			vaultSecret.base64Encoded = kv[1]
		default:
			return VaultSecret{}, fmt.Errorf("invalid key in %q: %s", encryptedSecret, kv[0])
		}
	}
	return vaultSecret, nil
}

func (v *VaultDecrypter) FetchVaultToken() (string, error) {
	if (VaultConfig{}) == v.vaultConfig {
		return "", fmt.Errorf("vault secrets not configured in service profile yaml")
	}
	if v.vaultConfig.AuthMethod == "TOKEN" {
		token := os.Getenv("VAULT_TOKEN")
		if token != "" {
			return token, nil
		} else {
			return "", fmt.Errorf("VAULT_TOKEN environment variable not set")
		}
	} else if v.vaultConfig.AuthMethod == "KUBERNETES" {
		if v.vaultConfig.Path == "" || v.vaultConfig.Role == "" {
			return "", fmt.Errorf("path and role both required for Kubernetes auth method")
		}
		return v.FetchServiceAccountToken()
	} else {
		return "", fmt.Errorf("unknown Vault secrets auth method: %q", v.vaultConfig.AuthMethod)
	}
}

func (v *VaultDecrypter) FetchServiceAccountToken() (string, error) {
	if (VaultConfig{}) == v.vaultConfig {
		return "", fmt.Errorf("vault secrets not configured in service profile yaml")
	}

	client, err := api.NewClient(&api.Config{
		Address: v.vaultConfig.Url,
	})
	if err != nil {
		return "", fmt.Errorf("error fetching vault client: %s", err)
	}

	tokenFile, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("error reading service account token: %s", err)
	}
	token := string(tokenFile)
	data := map[string]interface{}{
		"role": v.vaultConfig.Role,
		"jwt":  token,
	}

	secret, err := client.Logical().Write("auth/" + v.vaultConfig.Path + "/login", data)
	if err != nil {
		return "", fmt.Errorf("error logging into vault using kubernetes auth: %s", err)
	}

	return secret.Auth.ClientToken, nil
}

func (v *VaultDecrypter) FetchVaultClient(token string) (*api.Client, error) {
	if (VaultConfig{}) == v.vaultConfig {
		return &api.Client{}, fmt.Errorf("vault secrets not configured in service profile yaml")
	}
	client, err := api.NewClient(&api.Config{
		Address: v.vaultConfig.Url,
	})
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}

func (v *VaultDecrypter) FetchSecret(secret VaultSecret) (string, error) {
	client, err := v.FetchVaultClient(v.vaultConfig.Token)
	if err != nil {
		return "", fmt.Errorf("error fetching vault client - %s", err)
	}

	path := secret.engine + "/" + secret.path
	if _, ok := v.isKV2[secret.engine]; ok {
		path = secret.engine + "/data/" + secret.path
	}

	secretMapping, err := client.Logical().Read(path)
	if err != nil {
		if strings.Contains(err.Error(), "invalid character '<' looking for beginning of value") {
			// some connection errors aren't properly caught, and the vault client tries to parse <nil>
			return "", fmt.Errorf("error fetching secret from vault - check connection to the server: %s", v.vaultConfig.Url)
		}
		return "", fmt.Errorf("error fetching secret from vault: %s", err)
	}

	warnings := secretMapping.Warnings
	if warnings != nil {
		for i := range warnings {
			if strings.Contains(warnings[i], "Invalid path for a versioned K/V secrets engine") {
				// try again using K/V v2 path
				path = secret.engine + "/data/" + secret.path
				secretMapping, err = client.Logical().Read(path)
				if err != nil {
					return "", fmt.Errorf("error fetching secret from vault: %s", err)
				} else if secretMapping == nil {
					return "", fmt.Errorf("couldn't find vault path %q", path)
				}
				v.isKV2[secret.engine] = struct{}{}
				break
			}
		}
	}

	if secretMapping != nil {
		mapping := secretMapping.Data
		if data, ok := mapping["data"]; ok { // one more nesting of "data" if using K/V v2
			if submap, ok := data.(map[string]interface{}); ok {
				mapping = submap
			}
		}

		decrypted, ok := mapping[secret.key].(string)
		if !ok {
			return "", fmt.Errorf("error fetching key %q", secret.key)
		}
		return decrypted, nil
	}

	return "", nil
}

func (v *VaultDecrypter) RetryFetchSecret(secret VaultSecret) (string, error) {
	token, err := v.FetchVaultToken()
	if err != nil {
		return "", fmt.Errorf("error fetching vault token - %s", err)
	}
	v.vaultConfig.Token = token
	return v.FetchSecret(secret)
}