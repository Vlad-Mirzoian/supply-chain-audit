package reach

import "testing"

func TestScanJS(t *testing.T) {
	src := []byte(`
const express = require('express');
import { merge } from "lodash/merge";
import "@scope/side-effect/register";
export { x } from './local';
const m = await import('node:fs');
`)
	im := imports{names: map[string]bool{}}
	scanJS(src, &im)
	for _, n := range []string{"express", "lodash", "@scope/side-effect"} {
		if !im.names[n] {
			t.Errorf("missing %s in %v", n, im.names)
		}
	}
	if im.names["./local"] || im.names["fs"] || im.dynamic {
		t.Errorf("unexpected: %v dynamic=%v", im.names, im.dynamic)
	}
	scanJS([]byte(`const p = require(name)`), &im)
	if !im.dynamic {
		t.Error("dynamic require not detected")
	}
}

func TestScanPy(t *testing.T) {
	im := imports{names: map[string]bool{}}
	scanPy([]byte("import os, yaml as y\nfrom jinja2.sandbox import X\nfrom . import local\n"), &im)
	for _, n := range []string{"os", "yaml", "jinja2"} {
		if !im.names[n] {
			t.Errorf("missing %s in %v", n, im.names)
		}
	}
}
