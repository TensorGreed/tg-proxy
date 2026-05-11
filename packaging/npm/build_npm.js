#!/usr/bin/env node
//
// Assemble npm publish artifacts from a goreleaser dist/ directory.
//
// Produces:
//   <output>/tg-proxy/                       root shim package
//   <output>/tg-proxy-linux-x64/            platform package + binary
//   <output>/tg-proxy-linux-arm64/
//   <output>/tg-proxy-darwin-x64/
//   <output>/tg-proxy-darwin-arm64/
//   <output>/tg-proxy-win32-x64/
//   <output>/tg-proxy-win32-arm64/
//
// Each platform dir is publishable directly with `npm publish` in that
// directory. The root package's optionalDependencies are also pinned to
// the release version.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

const PLATFORMS = [
  { name: 'tg-proxy-linux-x64',    goos: 'linux',   goarch: 'amd64', os: 'linux',  cpu: 'x64'   },
  { name: 'tg-proxy-linux-arm64',  goos: 'linux',   goarch: 'arm64', os: 'linux',  cpu: 'arm64' },
  { name: 'tg-proxy-darwin-x64',   goos: 'darwin',  goarch: 'amd64', os: 'darwin', cpu: 'x64'   },
  { name: 'tg-proxy-darwin-arm64', goos: 'darwin',  goarch: 'arm64', os: 'darwin', cpu: 'arm64' },
  { name: 'tg-proxy-win32-x64',    goos: 'windows', goarch: 'amd64', os: 'win32',  cpu: 'x64'   },
  { name: 'tg-proxy-win32-arm64',  goos: 'windows', goarch: 'arm64', os: 'win32',  cpu: 'arm64' },
];

function parseArgsOrDie() {
  const { values } = parseArgs({
    options: {
      'dist-dir': { type: 'string' },
      version:    { type: 'string' },
      output:     { type: 'string' },
    },
  });
  for (const k of ['dist-dir', 'version', 'output']) {
    if (!values[k]) {
      process.stderr.write(
        `usage: build_npm.js --dist-dir <goreleaser-dist> --version <X.Y.Z> --output <dir>\n`,
      );
      process.exit(2);
    }
  }
  return values;
}

function findBinaries(distDir) {
  // Goreleaser writes paths relative to the cwd where it ran (typically the
  // repo root, which is dirname(distDir)). Absolute paths are honored. As a
  // fallback we also probe relative to distDir itself.
  const artifactsPath = path.join(distDir, 'artifacts.json');
  const artifacts = JSON.parse(fs.readFileSync(artifactsPath, 'utf8'));
  const map = new Map();
  for (const a of artifacts) {
    if (a.type !== 'Binary') continue;
    const key = `${a.goos}/${a.goarch}`;
    const candidates = [];
    if (path.isAbsolute(a.path)) {
      candidates.push(a.path);
    } else {
      candidates.push(path.resolve(path.dirname(distDir), a.path));
      candidates.push(path.resolve(distDir, a.path));
    }
    for (const c of candidates) {
      if (fs.existsSync(c)) {
        map.set(key, c);
        break;
      }
    }
  }
  return map;
}

function ensureEmptyDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
}

function writePlatformPackage(opts) {
  const { destRoot, plat, binary, version } = opts;
  const dir = path.join(destRoot, plat.name);
  ensureEmptyDir(path.join(dir, 'bin'));
  const binName = plat.goos === 'windows' ? 'tg-proxy.exe' : 'tg-proxy';
  fs.copyFileSync(binary, path.join(dir, 'bin', binName));
  if (plat.goos !== 'windows') {
    fs.chmodSync(path.join(dir, 'bin', binName), 0o755);
  }

  const pkg = {
    name: plat.name,
    version,
    description: `tg-proxy prebuilt binary for ${plat.os}-${plat.cpu}.`,
    license: 'MIT',
    repository: {
      type: 'git',
      url: 'git+https://github.com/TensorGreed/tg-proxy.git',
    },
    os:  [plat.os],
    cpu: [plat.cpu],
    files: ['bin'],
  };
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify(pkg, null, 2) + '\n',
  );

  // Drop a tiny README so npm doesn't warn.
  fs.writeFileSync(
    path.join(dir, 'README.md'),
    `# ${plat.name}\n\nDo not install this package directly; it is a ` +
      `dependency of the [tg-proxy](https://www.npmjs.com/package/tg-proxy) ` +
      `npm package.\n`,
  );
}

function writeRootPackage(opts) {
  const { destRoot, version, npmRoot, platforms } = opts;
  const dir = path.join(destRoot, 'tg-proxy');
  ensureEmptyDir(dir);
  ensureEmptyDir(path.join(dir, 'bin'));

  // Copy the shim verbatim.
  fs.copyFileSync(
    path.join(npmRoot, 'bin', 'tg-proxy.js'),
    path.join(dir, 'bin', 'tg-proxy.js'),
  );

  // Build pinned optionalDependencies from the platforms we actually built.
  const optionalDependencies = {};
  for (const p of platforms) optionalDependencies[p.name] = version;

  const pkg = JSON.parse(
    fs.readFileSync(path.join(npmRoot, 'package.json'), 'utf8'),
  );
  pkg.version = version;
  pkg.optionalDependencies = optionalDependencies;

  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify(pkg, null, 2) + '\n',
  );

  // README too.
  if (fs.existsSync(path.join(npmRoot, 'README.md'))) {
    fs.copyFileSync(
      path.join(npmRoot, 'README.md'),
      path.join(dir, 'README.md'),
    );
  }
}

function main() {
  const args = parseArgsOrDie();
  const distDir = path.resolve(args['dist-dir']);
  const output = path.resolve(args.output);
  const npmRoot = path.resolve(__dirname);
  const binaries = findBinaries(distDir);

  fs.mkdirSync(output, { recursive: true });

  const built = [];
  for (const plat of PLATFORMS) {
    const key = `${plat.goos}/${plat.goarch}`;
    const binary = binaries.get(key);
    if (!binary) {
      process.stderr.write(`WARN: no binary for ${key}; skipping ${plat.name}\n`);
      continue;
    }
    writePlatformPackage({ destRoot: output, plat, binary, version: args.version });
    built.push(plat);
    process.stdout.write(`  built ${plat.name}\n`);
  }
  if (built.length === 0) {
    process.stderr.write('ERROR: no platform packages built\n');
    process.exit(1);
  }

  writeRootPackage({ destRoot: output, version: args.version, npmRoot, platforms: built });
  process.stdout.write(`  built tg-proxy (root)\n`);
  process.stdout.write(
    `done; ${built.length + 1} package(s) staged under ${output}\n`,
  );
}

if (require.main === module) main();
module.exports = { PLATFORMS };
