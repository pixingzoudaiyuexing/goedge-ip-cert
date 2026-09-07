package main

import "testing"

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
