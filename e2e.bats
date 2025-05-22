#!/usr/bin/env bats

@test "Test containsAnyOf" {
	run kwctl run  --request-path test_data/deployment_containsAnyOf.json --settings-path test_data/settings_containsAnyOf.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Test doesNotContainAnyOf" {
	run kwctl run  --request-path test_data/deployment_doesNotContainAnyOf.json --settings-path test_data/settings_doesNotContainAnyOf.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Test containsAllOf" {
	run kwctl run  --request-path test_data/deployment_containsAllOf.json --settings-path test_data/settings_containsAllOf.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Test doesNotContainAllOf" {
	run kwctl run  --request-path test_data/deployment_doesNotContainAllOf.json --settings-path test_data/settings_doesNotContainAllOf.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

