// Unit tests for the npm shim and the build_npm helper.
//
// Run with: node --test test/
//
// Requires Node 18+ for the built-in test runner.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const shim = require('../bin/tg-proxy.js');
const { PLATFORMS } = require('../build_npm.js');

test('PLATFORMS covers all 6 supported combinations', () => {
  assert.equal(PLATFORMS.length, 6);
  const names = new Set(PLATFORMS.map((p) => p.name));
  for (const n of [
    'tg-proxy-linux-x64',
    'tg-proxy-linux-arm64',
    'tg-proxy-darwin-x64',
    'tg-proxy-darwin-arm64',
    'tg-proxy-win32-x64',
    'tg-proxy-win32-arm64',
  ]) {
    assert.ok(names.has(n), `missing ${n}`);
  }
});

test('PLATFORMS map Node os/cpu to Go GOOS/GOARCH correctly', () => {
  for (const p of PLATFORMS) {
    if (p.os === 'linux')   assert.equal(p.goos, 'linux');
    if (p.os === 'darwin')  assert.equal(p.goos, 'darwin');
    if (p.os === 'win32')   assert.equal(p.goos, 'windows');
    if (p.cpu === 'x64')    assert.equal(p.goarch, 'amd64');
    if (p.cpu === 'arm64')  assert.equal(p.goarch, 'arm64');
  }
});

test('resolveBinary exits with helpful message when no platform pkg is installed', () => {
  // Run the shim in a subprocess so its process.exit doesn't kill the
  // test process. Without the platform-specific dependency installed,
  // resolveBinary must print a hint pointing at `go install`.
  const proc = spawnSync(process.execPath, [
    require.resolve('../bin/tg-proxy.js'),
  ], { encoding: 'utf8' });

  assert.notEqual(proc.status, 0, `unexpectedly succeeded: ${proc.stdout}`);
  assert.match(proc.stderr, /no prebuilt binary/);
  assert.match(proc.stderr, /go install/);
});

test('build_npm assembles all packages from a synthetic dist/', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-proxy-npm-test-'));
  try {
    const dist = path.join(tmp, 'dist');
    fs.mkdirSync(dist, { recursive: true });

    // Create fake binaries.
    const artifacts = [];
    for (const p of PLATFORMS) {
      const subdir = path.join(dist, `${p.goos}_${p.goarch}`);
      fs.mkdirSync(subdir, { recursive: true });
      const binName = p.goos === 'windows' ? 'tg-proxy.exe' : 'tg-proxy';
      const binPath = path.join(subdir, binName);
      fs.writeFileSync(binPath, `#!/bin/sh\necho fake ${p.name}\n`);
      artifacts.push({
        type:   'Binary',
        goos:   p.goos,
        goarch: p.goarch,
        path:   binPath,
      });
    }
    fs.writeFileSync(path.join(dist, 'artifacts.json'), JSON.stringify(artifacts));

    const output = path.join(tmp, 'out');
    execFileSync(process.execPath, [
      require.resolve('../build_npm.js'),
      '--dist-dir', dist,
      '--version',  '9.9.9-test',
      '--output',   output,
    ], { stdio: 'pipe' });

    // Root package present with pinned optionalDependencies.
    const rootPkg = JSON.parse(
      fs.readFileSync(path.join(output, 'tg-proxy', 'package.json'), 'utf8'),
    );
    assert.equal(rootPkg.version, '9.9.9-test');
    for (const p of PLATFORMS) {
      assert.equal(rootPkg.optionalDependencies[p.name], '9.9.9-test');
    }
    assert.ok(fs.existsSync(path.join(output, 'tg-proxy', 'bin', 'tg-proxy.js')));

    // Every platform package has the right os/cpu and a binary in bin/.
    for (const p of PLATFORMS) {
      const pkg = JSON.parse(
        fs.readFileSync(path.join(output, p.name, 'package.json'), 'utf8'),
      );
      assert.deepEqual(pkg.os,  [p.os]);
      assert.deepEqual(pkg.cpu, [p.cpu]);
      assert.equal(pkg.version, '9.9.9-test');
      const binName = p.goos === 'windows' ? 'tg-proxy.exe' : 'tg-proxy';
      assert.ok(
        fs.existsSync(path.join(output, p.name, 'bin', binName)),
        `missing binary in ${p.name}`,
      );
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
