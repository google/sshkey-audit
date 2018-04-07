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
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	keyFile         = flag.String("keys", "", "File containing SSH pubkeys.")
	accountsFile    = flag.String("accounts", "", "File containing account definitions.")
	groupsFile      = flag.String("groups", "", "File containing group definitions.")
	matching        = flag.String("matching", ".*", "Only check hosts matching this regex.")
	flagAddMissing  = flag.Bool("add_missing", false, "Add missing keys as needed (always true for 'fix').")
	flagDeleteExtra = flag.Bool("delete_extra", false, "Delete extra keys as needed (always true for 'fix').")
	timeout         = flag.Duration("timeout", 20*time.Second, "Timeout per login.")
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

func checkAccount(ctx context.Context, kg map[string]*KeyGroup, account account) ([]key, []string, error) {
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
	var extra []key
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
			extra = append(extra, ck)
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

func deleteExtra(ctx context.Context, acct account, extra []key) error {
	var cmds []string
	for _, key := range extra {
		log.Infof("Deleting %q from %q", key.description, acct.account)
		tmpf := ".ssh/authorized_keys.tmp"
		ak := ".ssh/authorized_keys"
		cmds = append(cmds,
			fmt.Sprintf(`grep -v '^%s %s ' %s > %s`, key.algorithm, key.key, ak, tmpf),
			fmt.Sprintf(`chmod --reference=%s %s`, ak, tmpf),
			fmt.Sprintf(`mv %s %s`, tmpf, ak),
		)
	}
	return exec.CommandContext(ctx, "ssh", acct.account, strings.Join(cmds, " && ")).Run()
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
			fmt.Sprintf(`cp %s %s`, ak, tmpf),
			fmt.Sprintf(`chmod --reference=%s %s`, ak, tmpf),
			fmt.Sprintf(`echo "%s %s %s" >> %s`, k.algorithm, k.key, name, tmpf),
			fmt.Sprintf(`mv %s %s`, tmpf, ak),
		)
	}
	cmd := exec.CommandContext(ctx, "ssh", acct.account, strings.Join(cmds, " && "))
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func check(ctx context.Context, keys []key, kg map[string]*KeyGroup, accounts []account, doAddMissing, doDeleteExtra bool) error {
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
		ctx2, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		extra, missing, err := checkAccount(ctx2, kg, account)
		if err != nil {
			log.Errorf("Failed to check account %q: %v", account.account, err)
			continue
		}

		if len(extra) > 0 {
			var es []string
			for _, e := range extra {
				es = append(es, e.description)
			}
			log.Warningf("Extra keys: %q", es)
		}
		if len(missing) > 0 {
			log.Warningf("Missing keys: %q", missing)
		}
		if doAddMissing {
			if err := addMissing(ctx, keys, account, missing); err != nil {
				log.Errorf("Failed to add missing keys %q to %q: %v", missing, account, err)
			}
		}
		if doDeleteExtra {
			if err := deleteExtra(ctx, account, extra); err != nil {
				log.Errorf("Failed to delete extra keys %q from %q: %v", extra, account, err)
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

func commandExpand(accounts []account, keyGroups map[string]*KeyGroup, args []string) {
	fs := flag.NewFlagSet("expand", flag.ExitOnError)
	var (
		keysFlag = fs.String("keys", ".*", "Only consider keys matching regex.")
		showAll  = fs.Bool("show_all", false, "Show all hosts, even if they didn't have any matching keys.")
	)
	fs.Parse(flag.Args()[1:])
	if fs.NArg() > 0 {
		log.Fatalf("Extra args on cmdline: %q", fs.Args()[1:])
	}
	keysRE, err := regexp.Compile(*keysFlag)
	if err != nil {
		log.Printf("Invalid regex %q: %v", *matching, err)
	}
	re, err := regexp.Compile(*matching)
	if err != nil {
		log.Printf("Invalid regex %q: %v", *matching, err)
	}
	for _, a := range accounts {
		if !re.MatchString(a.account) {
			continue
		}
		var keys []string
		seen := make(map[string]bool)
		for _, kgn := range a.keyGroupNames {
			for _, k := range keyGroups[kgn].Keys() {
				if keysRE.MatchString(k.description) && !seen[k.description] {
					keys = append(keys, k.description)
					seen[k.description] = true
				}
			}
		}
		sort.Strings(keys)
		if len(keys) > 0 || *showAll {
			fmt.Printf("%s\n", a.account)
			if len(keys) > 0 {
				fmt.Printf("  %s\n", strings.Join(keys, "\n  "))
			}
		}
	}

}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			`Usage: %s [options] <command>

Commands:
   check     Check, but default don't change anything.
   expand    Print what key can log in where.
   fix       Fix reality to match what specs say.

Options:
`, os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		log.Fatalf("Command not specified. Supported commands: check, expand, fix")
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

	if command == "check" || command == "fix" {
		if flag.NArg() != 1 {
			log.Fatalf("Extra args on cmdline: %q", flag.Args()[1:])
		}
		ctx := context.Background()
		am, de := *flagAddMissing, *flagDeleteExtra
		if command == "fix" {
			am = true
			de = true
		}
		if err := check(ctx, keys, keyGroups, accounts, am, de); err != nil {
			log.Fatalf("Failed to check keys: %v", err)
		}
		log.Infof("Done")
	} else if command == "expand" {
		commandExpand(accounts, keyGroups, flag.Args()[1:])
	} else {
		log.Fatalf("Invalid command %q", command)
	}
}
