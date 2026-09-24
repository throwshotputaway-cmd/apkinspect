'use strict';

const {spawnSync} = require('node:child_process');
const {findPython, root, venvExists, venvPath, venvPython} = require('./runtime');

function run(command, args) {
  const result = spawnSync(command, args, {cwd: root, stdio: 'inherit'});
  if (result.error) {
    console.error('apkinspect: %s' % result.error.message);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

const system = findPython();
if (!system) {
  console.error(
    'apkinspect: Python 3.9 or newer is required. Install Python and rerun npm install.',
  );
  process.exit(1);
}

if (!venvExists()) {
  run(system.command, system.prefix.concat(['-m', 'venv', venvPath]));
}

run(venvPython(), [
  '-m',
  'pip',
  'install',
  '--disable-pip-version-check',
  '--no-input',
  '--quiet',
  root,
]);
