package code

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

func findingsOf(t *testing.T, typ, input string) []api.Finding {
	t.Helper()
	all, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	var out []api.Finding
	for _, f := range all {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

func TestScanner_Name(t *testing.T) { assert.Equal(t, "code", New().Name()) }

func TestScan_Empty(t *testing.T) {
	f, err := New().Scan(context.Background(), nil, api.Hints{})
	require.NoError(t, err)
	assert.Nil(t, f)
}

func TestScan_PythonDef(t *testing.T) {
	input := "Look at this: def compute_total(items):\n    return sum(items)"
	fs := findingsOf(t, "code.python_def", input)
	require.Len(t, fs, 1)
	assert.Equal(t, api.SeverityMedium, fs[0].Severity)
}

func TestScan_PythonClass(t *testing.T) {
	fs := findingsOf(t, "code.python_class", "class Order(BaseModel):\n  id: int")
	require.Len(t, fs, 1)
}

func TestScan_PythonImport(t *testing.T) {
	for _, input := range []string{
		"import os\n",
		"from collections import defaultdict\n",
	} {
		fs := findingsOf(t, "code.python_import", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_JavaScriptFunction(t *testing.T) {
	fs := findingsOf(t, "code.javascript_function", "function getUser(id) {")
	require.Len(t, fs, 1)
}

func TestScan_JavaScriptRequire(t *testing.T) {
	fs := findingsOf(t, "code.javascript_require", `const x = require("fs")`)
	require.Len(t, fs, 1)
}

func TestScan_JavaScriptConsole(t *testing.T) {
	fs := findingsOf(t, "code.javascript_console", "console.log(user)")
	require.Len(t, fs, 1)
}

func TestScan_GoFunc(t *testing.T) {
	for _, input := range []string{
		"func main() {",
		"func (s *Server) Start(ctx context.Context) error {",
		"func New() *Scanner { return &Scanner{} }",
	} {
		fs := findingsOf(t, "code.go_func", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_GoPackage(t *testing.T) {
	fs := findingsOf(t, "code.go_package", "package main\n\nimport \"fmt\"")
	require.Len(t, fs, 1)
}

func TestScan_CInclude(t *testing.T) {
	for _, input := range []string{
		`#include <stdio.h>`,
		`#include "config.h"`,
		` # include  <stdlib.h>`,
	} {
		fs := findingsOf(t, "code.c_include", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_JavaClassDecl(t *testing.T) {
	fs := findingsOf(t, "code.java_class_decl", "public class UserService {")
	require.Len(t, fs, 1)
}

func TestScan_Shebang(t *testing.T) {
	for _, input := range []string{
		"#!/bin/sh",
		"#!/usr/bin/env python3",
		"#!/usr/local/bin/zsh",
	} {
		fs := findingsOf(t, "code.shebang", input)
		assert.NotEmpty(t, fs, input)
	}
}

func TestScan_SQLCreate(t *testing.T) {
	fs := findingsOf(t, "code.sql_create", "CREATE TABLE users (id INT);")
	require.Len(t, fs, 1)
}

func TestScan_PlainTextNotFlagged(t *testing.T) {
	input := "Should we talk about the function and class hierarchy in the report?"
	findings, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestScan_FullScript(t *testing.T) {
	// A real Python script should produce multiple findings, not zero.
	script := strings.Join([]string{
		"#!/usr/bin/env python3",
		"import os",
		"from typing import List",
		"",
		"class Sales:",
		"    def total(self) -> int:",
		"        return 0",
		"",
	}, "\n")
	findings, err := New().Scan(context.Background(), []byte(script), api.Hints{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 4) // shebang + 2 imports + class + def
}

func TestScan_OffsetsArePrecise(t *testing.T) {
	input := "Code:\nfunc hello() {}\n\ndef hi():\n  pass\n"
	findings, err := New().Scan(context.Background(), []byte(input), api.Hints{})
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Greater(t, f.End, f.Start)
		assert.LessOrEqual(t, f.End, len(input))
		assert.Equal(t, "code", f.Scanner)
	}
}
