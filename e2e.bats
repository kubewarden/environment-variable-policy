#!/usr/bin/env bats

@test "Test anyIn" {
	run kwctl run  --request-path test_data/deployment_anyin.json --settings-path test_data/settings_anyin.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Test anyNotIn" {
	run kwctl run  --request-path test_data/deployment_anynotin.json --settings-path test_data/settings_anynotin.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Test allAreUsed" {
	run kwctl run  --request-path test_data/deployment_allareused.json --settings-path test_data/settings_allareused.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
 }

@test "Test notAllAreUsed" {
	run kwctl run  --request-path test_data/deployment_notallareused.json --settings-path test_data/settings_notallareused.json  annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
 }
