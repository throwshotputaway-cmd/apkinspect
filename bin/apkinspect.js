#!/usr/bin/env node
'use strict';

const path = require('node:path');
const {spawn, spawnSync} = require('node:child_process');
const {venvExists, venvPython} = require('./runtime');

const args = process.argv.slice(2);
if (!venvExists()) {
  console.error('apkinspect: initializing Python runtime...');
  const bootstrap = spawnSync(
    process.execPath,
    [path.join(__dirname, 'install-python.js')],
    {stdio: 'inherit'},
  );
  if (bootstrap.error) {
    console.error('apkinspect: %s' % bootstrap.error.message);
    process.exit(1);
  }
  if (bootstrap.status !== 0) {
    process.exit(bootstrap.status || 1);
  }
}

const child = spawn(
  venvPython(),
  ['-m', 'apkinspect', ...args],
  {stdio: 'inherit', env: process.env},
);
child.on('error', (error) => {
  console.error('apkinspect: %s' % error.message);
  process.exitCode = 1;
});
child.on('exit', (code, signal) => {
  if (signal) {
    process.exitCode = 128;
    return;
  }
  process.exitCode = code === null ? 1 : code;
});
