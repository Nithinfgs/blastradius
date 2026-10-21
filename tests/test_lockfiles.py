from __future__ import annotations

import json

from blastradius.lockfiles import parse_lockfile, parser_for


def pins(name, text):
    return set(parse_lockfile(name, text))


def test_requirements():
    text = "# c\nrequests==2.31.0 \\\n    --hash=sha256:abc\nEvil_Pkg[extra]==1.107.0 ; python_version>'3'\nflask>=2\n"
    assert pins("requirements.txt", text) == {
        ("pypi", "requests", "2.31.0"),
        ("pypi", "Evil_Pkg", "1.107.0"),
    }
    assert parser_for("requirements-dev.txt") is not None
    assert parser_for("notes.txt") is None


def test_uv_poetry_cargo_toml_blocks():
    text = '[[package]]\nname = "evil-pkg"\nversion = "1.107.0"\nsource = { registry = "x" }\n\n[[package]]\nname = "ok"\nversion = "0.1"\n'
    assert ("pypi", "evil-pkg", "1.107.0") in pins("uv.lock", text)
    assert ("pypi", "ok", "0.1") in pins("poetry.lock", text)
    assert ("crates", "evil-pkg", "1.107.0") in pins("Cargo.lock", text)


def test_pipfile_lock():
    data = {"default": {"evil-pkg": {"version": "==1.107.0"}, "git": {"git": "x"}}, "develop": {}}
    assert pins("Pipfile.lock", json.dumps(data)) == {("pypi", "evil-pkg", "1.107.0")}


def test_package_lock_v3_and_legacy():
    v3 = {
        "packages": {
            "": {"name": "root"},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/a/node_modules/@scope/bad": {"version": "2.0.3"},
        }
    }
    assert pins("package-lock.json", json.dumps(v3)) == {
        ("npm", "a", "1.0.0"),
        ("npm", "@scope/bad", "2.0.3"),
    }
    legacy = {
        "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
            "c": {"version": "file:../c"},
        }
    }
    assert pins("package-lock.json", json.dumps(legacy)) == {("npm", "a", "1.0.0"), ("npm", "b", "2.0.0")}


def test_yarn_v1_and_berry():
    v1 = '"@scope/bad@^2.0.0", "@scope/bad@^2.0.1":\n  version "2.0.3"\n  resolved "x"\n\nleft-pad@^1.0.0:\n  version "1.3.0"\n'
    assert pins("yarn.lock", v1) == {("npm", "@scope/bad", "2.0.3"), ("npm", "left-pad", "1.3.0")}
    berry = '"left-pad@npm:^1.0.0":\n  version: 1.3.0\n  resolution: "left-pad@npm:1.3.0"\n'
    assert pins("yarn.lock", berry) == {("npm", "left-pad", "1.3.0")}


def test_pnpm_lock():
    text = "packages:\n\n  /left-pad@1.3.0:\n    resolution: {}\n\n  '@scope/bad@2.0.3(peer@1.0.0)':\n    x: 1\n\n  /@old/pkg/4.5.6:\n    y: 2\n"
    assert pins("pnpm-lock.yaml", text) == {
        ("npm", "left-pad", "1.3.0"),
        ("npm", "@scope/bad", "2.0.3"),
        ("npm", "@old/pkg", "4.5.6"),
    }


def test_go_sum():
    text = "github.com/x/y v1.2.3 h1:abc=\ngithub.com/x/y v1.2.3/go.mod h1:def=\n"
    assert pins("go.sum", text) == {("go", "github.com/x/y", "1.2.3")}


def test_malformed_json_yields_nothing():
    assert pins("package-lock.json", "{oops") == set()
    assert pins("Pipfile.lock", "[]") == set()
