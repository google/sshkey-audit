// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	keyFile      = flag.String("keys", "", "File containing SSH pubkeys.")
	accountsFile = flag.String("accounts", "", "File containing account definitions.")
	groupsFile   = flag.String("groups", "", "File containing group definitions.")
	matching     = flag.String("matching", ".*", "Only check hosts matching this regex.")
	doAddMissing = flag.Bool("add_missing", false, "Add missing keys as needed.")
)

type key struct {
	algorithm   string
	key         string
	description string
}

type account struct {
	account       string
	keyGroupNames []string
}

func parseKeys(b []byte) ([]key, error) {
	var keys []key
	seen := make(map[string]string)
	re := regexp.MustCompile(`(?m)^([^\s#]+)\s+([^\s]+)\s+(.*)$`)
	for _, e := range re.FindAllStringSubmatch(string(b), -1) {
		if _, found := seen[e[3]]; found {
			return nil, fmt.Errorf("key ID %q listed more than once", e[3])
		}
		if prev, found := seen[e[2]]; found {
			return nil, fmt.Errorf("key %q is same as %q", e[3], prev)
		}
		keys = append(keys, key{
			algorithm:   e[1],
			key:         e[2],
			description: e[3],
		})
		seen[e[2]] = e[3]
		seen[e[3]] = e[3]
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
			account:       e[1],
			keyGroupNames: strings.Split(e[2], " "),
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
	log.Debugf("Found %d current keys", len(currentKeys))

	// Check for extra keys.
	var extra []string
	for _, ck := range currentKeys {
		found := false
		for _, kn := range account.keyGroupNames {
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
	checked := make(map[string]bool)
	for _, kgn := range account.keyGroupNames {
		for _, k := range kg[kgn].Keys() {
			if checked[k.key] {
				continue
			}
			checked[k.key] = true
			found := false
			for _, ck := range currentKeys {
				if k.key == ck.key {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, k.description)
			}
		}
	}
	return extra, missing, nil
}

func addMissing(ctx context.Context, keys []key, acct account, missing []string) error {
	var cmds []string
	for _, name := range missing {
		log.Infof("Adding %q to %q", name, acct.account)
		var k *key
		for _, t := range keys {
			if name == t.description {
				k = &t
				break
			}
		}
		if k == nil {
			log.Fatalf("Internal error: missing key %q, but can't find it", name)
		}

		// TODO: random tmpfile name.
		tmpf := ".ssh/authorized_keys.tmp"
		ak := ".ssh/authorized_keys"
		cmds = append(cmds,
			fmt.Sprintf(`cp %s %s`+
				` && echo "%s %s %s" >> %s`+
				` && mv %s %s`,
				ak, tmpf,
				k.algorithm, k.key, name, tmpf,
				tmpf, ak,
			))
	}
	cmd := exec.CommandContext(ctx, "ssh", acct.account, strings.Join(cmds, " && "))
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func check(ctx context.Context, keys []key, kg map[string]*KeyGroup, accounts []account) error {
	log.Infof("Checking accounts…")
	re, err := regexp.Compile(*matching)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if re.FindString(account.account) == "" {
			continue
		}

		log.Infof("Checking %q", account.account)
		ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		extra, missing, err := checkAccount(ctx2, kg, account)
		if err != nil {
			log.Errorf("Failed to check account %q: %v", account.account, err)
			continue
		}

		if len(extra) > 0 {
			log.Warningf("Extra keys: %q", extra)
		}
		if len(missing) > 0 {
			log.Warningf("Missing keys: %q", missing)
		}
		if *doAddMissing {
			if err := addMissing(ctx, keys, account, missing); err != nil {
				log.Errorf("Failed to add missing keys %q to %q: %v", missing, account, err)
			}
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
	if flag.NArg() != 1 {
		log.Fatalf("Command not specified. Supported commands: check, expand")
	}
	command := flag.Arg(0)

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
		for _, kn := range a.keyGroupNames {
			if _, found := keyGroups[kn]; !found {
				log.Fatalf("Unknown key %q for account %q", kn, a.account)
			}
		}
	}
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].account < accounts[j].account
	})

	if command == "check" {
		ctx := context.Background()
		if err := check(ctx, keys, keyGroups, accounts); err != nil {
			log.Fatalf("blah: %v", err)
		}
		log.Infof("Done")
	} else if command == "expand" {
		re, err := regexp.Compile(*matching)
		if err != nil {
			log.Printf("Invalid regex %q: %v", *matching, err)
		}
		for _, a := range accounts {
			if re.FindString(a.account) == "" {
				continue
			}
			var keys []string
			seen := make(map[string]bool)
			for _, kgn := range a.keyGroupNames {
				for _, k := range keyGroups[kgn].Keys() {
					if !seen[k.description] {
						keys = append(keys, k.description)
						seen[k.description] = true
					}
				}
			}
			sort.Strings(keys)
			fmt.Printf("%s\n  %s\n", a.account, strings.Join(keys, "\n  "))
		}
	} else {
		log.Fatalf("Invalid command %q", command)
	}
}
