// Runner self-test for tools/csaf-validate/csaf_validate.mjs.
//
// Usage:  node tools/csaf-validate/test_csaf_validate.mjs [<known-valid.csaf.json>]
//
// Requires @secvisogram/csaf-validator-lib to be installed (CI installs the
// pin in tools/csaf-validate/package.json).

import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const RUNNER = join(HERE, 'csaf_validate.mjs')

function run(args) {
  return spawnSync(process.execPath, [RUNNER, ...args], { encoding: 'utf8' })
}

let failures = 0
function check(name, ok) {
  if (ok) {
    console.log(`ok   - ${name}`)
  } else {
    failures++
    console.error(`FAIL - ${name}`)
  }
}

check('no args exits 2 (usage)', run([]).status === 2)

const tmp = mkdtempSync(join(tmpdir(), 'csaf-selftest-'))
try {
  const badDoc = join(tmp, 'bad.csaf.json')
  writeFileSync(badDoc, JSON.stringify({
    document: { category: 'csaf_security_advisory', csaf_version: '2.0' },
  }))
  check('non-conformant document exits 1', run([badDoc]).status === 1)

  const junk = join(tmp, 'junk.csaf.json')
  writeFileSync(junk, '{ not valid json')
  check('unparsable document exits non-zero', run([junk]).status !== 0)

  const validDoc = process.argv[2]
  if (validDoc) {
    check(`valid document exits 0 (${validDoc})`, run([validDoc]).status === 0)
  } else {
    console.log('skip - valid-document exit-0 check (no valid doc path given)')
  }
} finally {
  rmSync(tmp, { recursive: true, force: true })
}

console.log(failures === 0 ? 'PASS' : `FAILED (${failures})`)
process.exit(failures === 0 ? 0 : 1)
