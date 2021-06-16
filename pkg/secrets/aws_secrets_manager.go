package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"strings"
)

const (
	Region                                 = "r"
	SecretName                             = "s"
	SecretKey                              = "k"
	GenericMalformedKeyError               = "Secret Format Error - Malformed parameters. Expected format '[encrypted|encryptedFile]:secrets:secrets-manager!r:<some-region>!s:<some-secret>' optionally followed by the parameter '!k:<some-params>' for types of encrypted to get a specific value in a key-value map."
	EncryptedFilesShouldNotSpecifyKeyError = "Encrypted files for AWS Secrets Manager should not include the !k:<some-params> token. Point to a binary secret in AWS Secrets Manager."
	RegionMissingError                     = "Secret format error - 'r' for the AWS region where the secret is stored is required."
	SecretNameMissingError                 = "Secret format error - 's' for the secret name is required."
	MalformedKVPairSecretPayload           = "Malformed key-value pair secret payload. Expected the payload to be a parameter value pair map of type: map[string]string."
)

type AwsSecretsManagerDecrypter struct {
	region                  string
	secretName              string
	secretKey               string
	isFile                  bool
	awsSecretsManagerClient AwsSecretsManagerClient
}

func NewAwsSecretsManagerDecrypter(ctx context.Context, isFile bool, params string) (Decrypter, error) {
	awsSMDecrypter := &AwsSecretsManagerDecrypter{isFile: isFile}
	if err := awsSMDecrypter.parse(params); err != nil {
		return nil, err
	}
	smClient, err := NewAwsSecretsManagerClient(awsSMDecrypter.region)
	if err != nil {
		return nil, err
	}
	awsSMDecrypter.awsSecretsManagerClient = smClient
	return awsSMDecrypter, nil
}

func (a *AwsSecretsManagerDecrypter) Decrypt() (string, error) {
	secretValue, err := a.awsSecretsManagerClient.FetchSecret(a.secretName)
	if err != nil {
		return "", err
	}

	if a.isFile { // The secret is assumed to be a file so extract the binary data from the secretValue
		if len(secretValue.SecretBinary) > 0 { // if the binary data has bytes then its a binary blob
			return parseBinaryFile(secretValue)
		}
		// else assume its a plaintext payload for a new file.
		return parsePlaintextFile(secretValue)

	} else if a.secretKey != "" { // The secret is assumed to be a k,v pair return the v
		return parseSecretKVPair(secretValue, a.secretKey)
	}

	// The secret is assumed to be a plaintext value return the value
	return parseSecretValue(secretValue)
}

func (a *AwsSecretsManagerDecrypter) IsFile() bool {
	return a.isFile
}

func (a *AwsSecretsManagerDecrypter) parse(params string) error {
	// Parse the user supplied params to get a map of the k,v pairs
	var data = make(map[string]string)
	entries := strings.Split(params, "!")
	if len(entries) < 2 {
		return fmt.Errorf(GenericMalformedKeyError)
	}
	for _, entry := range entries {
		kvPair := strings.SplitN(entry, ":", 2)
		if len(kvPair) != 2 {
			return fmt.Errorf(GenericMalformedKeyError)
		}
		data[kvPair[0]] = kvPair[1]
	}

	// Validate and save the required / known fields
	if region := data[Region]; region != "" {
		a.region = region
		delete(data, Region)
	} else {
		return fmt.Errorf(RegionMissingError)
	}

	if secretName := data[SecretName]; secretName != "" {
		a.secretName = secretName
		delete(data, SecretName)
	} else {
		return fmt.Errorf(SecretNameMissingError)
	}

	if secretKey := data[SecretKey]; secretKey != "" {
		a.secretKey = secretKey
		delete(data, SecretKey)
	}

	if a.isFile && a.secretKey != "" {
		return fmt.Errorf(EncryptedFilesShouldNotSpecifyKeyError)
	}

	if len(data) > 0 {
		return fmt.Errorf(GenericMalformedKeyError)
	}

	return nil
}

func parseBinaryFile(secretValue *secretsmanager.GetSecretValueOutput) (string, error) {
	return ToTempFile(secretValue.SecretBinary)
}

func parsePlaintextFile(secretValue *secretsmanager.GetSecretValueOutput) (string, error) {
	return ToTempFile([]byte(*secretValue.SecretString))
}

func parseSecretValue(secretValue *secretsmanager.GetSecretValueOutput) (string, error) {
	return *secretValue.SecretString, nil
}

func parseSecretKVPair(secretValue *secretsmanager.GetSecretValueOutput, key string) (string, error) {
	if secretValue.SecretString == nil {
		return "", fmt.Errorf(MalformedKVPairSecretPayload)
	}
	valueAsByteArray := []byte(*secretValue.SecretString)
	kvPairs := make(map[string]interface{})
	err := json.Unmarshal(valueAsByteArray, &kvPairs)

	if err != nil {
		return "", fmt.Errorf(MalformedKVPairSecretPayload)
	}

	untypedValue := kvPairs[key]
	valueForKeyAsString, ok := untypedValue.(string)
	if !ok {
		return "", fmt.Errorf(MalformedKVPairSecretPayload)
	}
	return valueForKeyAsString, nil
}
