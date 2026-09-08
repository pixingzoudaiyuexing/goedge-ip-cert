package main

import (
	"strings"
	"testing"
)

func TestRunOnceSafetyModesRequireApplyAndAreMutuallyExclusive(t *testing.T) {
	for _, args := range [][]string{
		{"run-once", "--timer"},
		{"run-once", "--manual-first-issue-retry"},
	} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "仅可与 --apply") {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
	err := run([]string{"run-once", "--apply", "--timer", "--manual-first-issue-retry"})
	if err == nil || !strings.Contains(err.Error(), "不能同时使用") {
		t.Fatalf("mutually exclusive modes err=%v", err)
	}
}

func TestValidateDSNAllowsOnlyExpectedDatabaseAndLocalTransport(t *testing.T) {
	for _, value := range []string{
		"user:secret@tcp(127.0.0.1:3306)/edges?parseTime=true",
		"user:secret@tcp([::1]:3306)/edges?parseTime=true",
		"user:secret@unix(/run/mysqld/mysqld.sock)/edges?parseTime=true",
	} {
		if err := validateDSN(value, "edges"); err != nil {
			t.Fatalf("local DSN rejected: %v", err)
		}
	}
	for _, value := range []string{
		"user:secret@tcp(203.0.113.10:3306)/edges?parseTime=true",
		"user:secret@tcp(127.0.0.1:3306)/other?parseTime=true",
		"user:secret@udp(127.0.0.1:3306)/edges?parseTime=true",
		"user:secret@tcp(127.0.0.1:3306)/edges?multiStatements=true",
		"user:secret@tcp(127.0.0.1:3306)/edges?allowAllFiles=true",
		"user:secret@tcp(127.0.0.1:3306)/edges?allowCleartextPasswords=true",
	} {
		if err := validateDSN(value, "edges"); err == nil {
			t.Fatalf("unsafe DSN accepted: %s", value)
		}
	}
}
