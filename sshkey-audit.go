package main

import (
	"bytes"
	"context"
	"flag"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	keyFile      = flag.String("keys", "", "")
	accountsFile = flag.String("accounts", "", "")
	groupsFile   = flag.String("groups", "", "")
)

type key struct {
	algorithm   string
	key         string
	description string
}

type account struct {
	account  string
	keyNames []string
}

func parseKeys(b []byte) ([]key, error) {
	var keys []key
	re := regexp.MustCompile(`(?m)^([^\s#]+)\s+([^\s]+)\s+(.*)$`)
	for _, e := range re.FindAllStringSubmatch(string(b), -1) {
		keys = append(keys, key{
			algorithm:   e[1],
			key:         e[2],
			description: e[3],
		})
	}
	return keys, nil
}

func readKeys(fn string) ([]key, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	return parseKeys(b)
}

func readAccounts(fn string) ([]account, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	var accounts []account
	re := regexp.MustCompile(`(?m)^([^#\s]+)\s+(.*)$`)
	for _, e := range re.FindAllStringSubmatch(string(b), -1) {
		accounts = append(accounts, account{
			account:  e[1],
			keyNames: strings.Split(e[2], " "),
		})
	}
	return accounts, nil
}

func readGroups(fn string) (map[string][]string, error) {
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	groups := map[string][]string{}
	re := regexp.MustCompile(`(?m)^([^#\s]+)\s+(.*)$`)
	for _, e := range re.FindAllStringSubmatch(string(b), -1) {
		groups[e[1]] = strings.Split(e[2], " ")
	}
	return groups, nil
}

func checkAccount(ctx context.Context, kg map[string]*KeyGroup, account account) ([]string, []string, error) {
	cmd := exec.CommandContext(ctx, "ssh", account.account, "cat .ssh/authorized_keys")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, nil, err
	}
	var err error
	currentKeys, err := parseKeys(buf.Bytes())
	if err != nil {
		return nil, nil, err
	}

	// Check for extra keys.
	var extra []string
	for _, ck := range currentKeys {
		found := false
		for _, kn := range account.keyNames {
			a := kg[kn]
			if a.Has(ck.key) {
				found = true
				break
			}
		}
		if !found {
			extra = append(extra, ck.description)
		}
	}

	// Check for missing keys.
	var missing []string
	for _, kn := range account.keyNames {
		found := false
		for _, ck := range currentKeys {
			a := kg[kn]
			if a.Has(ck.key) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, kn)
		}
	}
	return extra, missing, nil
}

func check(ctx context.Context, kg map[string]*KeyGroup, accounts []account) error {
	log.Infof("Checking accounts…")
	for n := range accounts {
		log.Infof("Checking %q", accounts[n].account)
		ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		extra, missing, err := checkAccount(ctx2, kg, accounts[n])
		if err != nil {
			log.Errorf("Failed to check account %q: %v", accounts[n].account, err)
			continue
		}

		if len(extra) > 0 {
			log.Warningf("Extra keys: %q", extra)
		}
		if len(missing) > 0 {
			log.Warningf("Missing keys: %q", missing)
		}
	}
	return nil
}

type KeyGroup struct {
	keys []key
}

func NewKeyGroup() *KeyGroup {
	return &KeyGroup{}
}

func (k *KeyGroup) Has(key string) bool {
	for _, k2 := range k.keys {
		if key == k2.key {
			return true
		}
	}
	return false
}

func (k *KeyGroup) Add(ky ...key) {
	k.keys = append(k.keys, ky...)
}

func (k *KeyGroup) Keys() []key {
	return k.keys
}

func main() {
	flag.Parse()

	// Read keys.
	keys, err := readKeys(*keyFile)
	if err != nil {
		log.Fatalf("Failed to read keyfile %q: %v", *keyFile, err)
	}
	log.Infof("Read %d keys", len(keys))

	// Make keygroups.
	keyGroups := map[string]*KeyGroup{}
	for _, k := range keys {
		kg := NewKeyGroup()
		kg.Add(k)
		keyGroups[k.description] = kg
	}

	groups, err := readGroups(*groupsFile)
	if err != nil {
		log.Fatalf("Failed to read groups file %q: %v", *groupsFile, err)
	}
	log.Infof("Read %d groups", len(groups))
	for g, ks := range groups {
		kg := NewKeyGroup()
		for _, kn := range ks {
			o, found := keyGroups[kn]
			if !found {
				log.Fatalf("Group %q refers to non-existing key %q", g, kn)
			}
			kg.Add(o.Keys()...)
		}
		keyGroups["@"+g] = kg
	}

	// Read accounts.
	accounts, err := readAccounts(*accountsFile)
	if err != nil {
		log.Fatalf("Failed to read accounts file %q: %v", *accountsFile, err)
	}
	log.Infof("Read %d accounts", len(accounts))

	// Verify that all accounts' keys exist in database.
	for _, a := range accounts {
		for _, kn := range a.keyNames {
			if _, found := keyGroups[kn]; !found {
				log.Fatalf("Unknown key %q for account %q", kn, a.account)
			}
		}
	}

	// Check all accounts.
	ctx := context.Background()
	if err := check(ctx, keyGroups, accounts); err != nil {
		log.Fatalf("blah: %v", err)
	}

}
