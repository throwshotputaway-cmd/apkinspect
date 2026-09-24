'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

const root = path.resolve(__dirname, '..');
const configuredVenv = process.env.APKINSPECT_VENV;
const venvPath = configuredVenv
  ? path.resolve(configuredVenv)
  : path.join(root, '.apkinspect-venv');

function systemPythonCandidates() {
  const candidates = [];
  if (process.env.APKINSPECT_PYTHON) {
    candidates.push({command: process.env.APKINSPECT_PYTHON, prefix: []});
  }
  if (process.platform === 'win32') {
    candidates.push(
      {command: 'py', prefix: ['-3']},
      {command: 'python', prefix: []},
      {command: 'python3', prefix: []},
    );
  } else {
    candidates.push(
      {command: 'python3', prefix: []},
      {command: 'python', prefix: []},
    );
  }
  return candidates;
}

function findPython() {
  for (const candidate of systemPythonCandidates()) {
    const result = spawnSync(
      candidate.command,
      candidate.prefix.concat(['-c', 'import sys; print(sys.executable)']),
      {encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']},
    );
    if (!result.error && result.status === 0) {
      return {...candidate, executable: result.stdout.trim()};
    }
  }
  return null;
}

function venvPython() {
  const relative = process.platform === 'win32'
    ? path.join('Scripts', 'python.exe')
    : path.join('bin', 'python');
  return path.join(venvPath, relative);
}

function venvExists() {
  return fs.existsSync(venvPython());
}

module.exports = {findPython, root, venvExists, venvPath, venvPython};
