package config

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/_metalogic_/log"
)

const secretsDir = "/var/run/secrets/"

// applications that use encrypted secrets must set this as a package global
var DecryptionKey string

// IfGetenv returns the value of environment variable name if found, else deflt
func IfGetenv(name, deflt string) (value string) {
	value = os.Getenv(name)
	if value == "" {
		value = deflt
	}
	return value
}

// MustGetenv returns the value of environment variable name;
// if name is not found exit with fatal error
func MustGetenv(name string) (v string) {
	v = os.Getenv(name)
	if v == "" {
		log.Fatalf("environment variable '%s' must be set", name)
	}
	return v
}

// IfGetBool returns the int value of environment variable name;
// if name is not found or value cannot be parsed as an int return deflt
func IfGetBool(name string, deflt bool) (value bool) {
	env := os.Getenv(name)
	if env != "" {
		value = (env == "1" || env == "true")
		return value
	}
	return deflt
}

// MustGetBool returns the int value of environment variable name;
// if name is not found or value cannot be parsed as an int exit with fatal error
func MustGetBool(name string) (value bool) {
	env := os.Getenv(name)
	if env == "" {
		log.Fatalf("environment variable '%s' must be set", name)
	}
	value = (env == "1" || env == "true")
	return value

}

// IfGetDuration returns the time.Duration value of environment variable name;
// if name is not found or value cannot be parsed as a time.Duration return deflt
func IfGetDuration(name string, deflt time.Duration) (value time.Duration) {
	env := os.Getenv(name)
	if env != "" {
		var err error
		value, err = time.ParseDuration(env)
		if err != nil {
			log.Errorf("failed to parse duration '%s': %s; using default value %v", name, err, deflt)
			return deflt
		}
		return value
	}
	return deflt
}

// MustGetDuration returns the time.Duration value of environment variable name;
// if name is not found or value cannot be parsed as a time.Duration exit with fatal error
func MustGetDuration(name string) (value time.Duration) {
	env := os.Getenv(name)
	if env == "" {
		log.Fatalf("environment variable '%s' must be set", name)
	}
	var err error
	value, err = time.ParseDuration(env)
	if err != nil {
		log.Fatal(err.Error())
	}
	return value
}

// IfGetInt returns the int value of environment variable name;
// if name is not found or value cannot be parsed as an int return deflt
func IfGetInt(name string, deflt int) (value int) {
	env := os.Getenv(name)
	if env != "" {
		var err error
		value, err = strconv.Atoi(env)
		if err != nil {
			log.Error(err.Error())
			return deflt
		}
		return value
	}
	return deflt
}

// MustGetInt returns the int value of environment variable name;
// if name is not found or value cannot be parsed as an int exit with fatal error
func MustGetInt(name string) (value int) {
	env := os.Getenv(name)
	if env == "" {
		log.Fatalf("environment variable '%s' must be set", name)
	}
	var err error
	value, err = strconv.Atoi(env)
	if err != nil {
		log.Fatal(err.Error())
	}
	return value

}

// IfGetRune returns the rune value of environment variable name;
// if name is not found or value cannot be parsed as an rune return deflt
func IfGetRune(name string, deflt rune) (rvalue rune) {
	env := os.Getenv(name)
	if env != "" {
		cleaned := strings.Replace(env, "0x", "", -1)
		value, err := strconv.ParseUint(cleaned, 16, 64)
		if err != nil {
			log.Error(err.Error())
			return deflt
		}
		return rune(value)
		// r := []rune(env)
		// return r[1]
	}
	return deflt
}

// MustGetRune returns the rune value of environment variable name;
// if name is not found or value cannot be parsed as an rune return deflt
func MustGetRune(name string, deflt rune) (rvalue rune) {
	env := os.Getenv(name)
	if env == "" {
		log.Fatalf("environment variable '%s' must be set", name)
	}

	cleaned := strings.Replace(env, "0x", "", -1)
	value, err := strconv.ParseUint(cleaned, 16, 64)
	if err != nil {
		log.Error(err.Error())
		return deflt
	}
	return rune(value)
	// r := []rune(env)
	// return r[1]

	return deflt
}

// GetSecret returns the value of Docker secret
func GetSecret(name string) (secret string, err error) {
	name = strings.ToUpper(name)
	bytes, err := ioutil.ReadFile(secretsDir + name)
	if err != nil {
		return secret, err
	}
	return string(bytes), nil
}

// GetDecryptedSecret returns the decrypted value of an encrypted Docker secret
func GetDecryptedSecret(name string, key []byte) (secret string, err error) {
	name = strings.ToUpper(name)
	data, err := ioutil.ReadFile(secretsDir + name)
	if err != nil {
		return secret, err
	}
	secret, err = Decrypt(string(data), key)
	if err != nil {
		return secret, err
	}
	return secret, nil
}

// GetRawSecret returns the raw value of Docker secret
func GetRawSecret(name string) (secret []byte, err error) {
	name = strings.ToUpper(name)
	secret, err = ioutil.ReadFile(secretsDir + name)
	if err != nil {
		return secret, err
	}
	return secret, nil
}

// MustGetSecret returns the value of the Docker secret with name;
// if the secret cannot be read exit with fatal error
func MustGetSecret(name string) string {
	secret, err := GetSecret(name)
	if err != nil || secret == "" {
		log.Fatalf("secret " + name + " not configured")
	}
	// if we have a decryption key then try to decrypt; otherwise
	// just return the secret
	if DecryptionKey != "" {
		decrypted, err := Decrypt(secret, []byte(DecryptionKey))
		if err == nil {
			return decrypted
		}
	}
	return secret
}

// MustGetConfig returns the value of the Docker secret with name, if it exists;
// if the secret cannot be read, returns the value of environment variable name;
// if name is not found in either Docker secrets or as an environment variable, exit with fatal error
func MustGetConfig(name string) string {
	var config string
	var err error
	config, err = GetSecret(name)
	if err != nil || config == "" {
		config = os.Getenv(name)
		if config == "" {
			log.Fatalf("MustGetConfig(" + name + ") failed configuration")
		}
	}
	return config
}

// decrypt decrypts encrypt string with a secret key and returns plain string.
func decrypt(encodedData string, secret []byte) (string, error) {
	encryptData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		return "", err
	}

	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(encryptData) < nonceSize {
		return "", err
	}

	nonce, cipherText := encryptData[:nonceSize], encryptData[nonceSize:]
	plainData, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainData), nil
}
