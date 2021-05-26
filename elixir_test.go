package main

import "testing"

// These are not complete tests of all functions in elixir. New tests should
// be added as the code is updated.

func TestRemoveHost(t *testing.T) {
	if removeHost("test1") != "test1" {
		t.Error("removeHost should return the input string when given 'test1'")
	}
	if removeHost("test2@test.com") != "test2" {
		t.Error("removeHost should return 'test2' when given 'test2@test.com'")
	}
	if removeHost("test3@test@test.com") != "test3" {
		t.Error("removeHost should return 'test3' when given " +
			"'test3@test@test.com'")
	}
}
