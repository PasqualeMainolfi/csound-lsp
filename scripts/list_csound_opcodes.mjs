#!/usr/bin/env node
// Writes resources/csound_opcodes.json: the opcodes of the latest published Csound, with their signatures.
//
// The server embeds the file and uses it only when neither the installed Csound nor the cached
// listing of a previous run is available, so that opcodes without a manual page (printfi, eventi, ...)
// are not reported as unknown. The release workflow runs this script before building, so every
// release carries the opcodes of the latest @csound/browser, the wasm build of Csound:
//
//     npm install --no-save --no-package-lock @csound/browser@latest
//     node scripts/list_csound_opcodes.mjs
//
// CSOUND_BROWSER can point to another build (e.g. .../node_modules/@csound/browser/dist/csound.js).
import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const OPCODE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const output = fileURLToPath(new URL('../resources/csound_opcodes.json', import.meta.url));

// the bundle is written for browsers and workers
globalThis.self ??= globalThis;
globalThis.window ??= globalThis;

// the package only declares a `module` entry, which bundlers read and Node doesn't
const module = process.env.CSOUND_BROWSER ? pathToFileURL(process.env.CSOUND_BROWSER).href : '@csound/browser/dist/csound.js';
const { libcsound } = await import(module);
const lib = await libcsound();
const csound = lib.csoundCreate();
const factory = lib.csoundUgenFactoryNew(csound);
const entries = lib.csoundUgenListOpcodes(factory);
const version = lib.csoundGetVersion();
lib.csoundUgenFactoryDelete(factory);
lib.csoundDestroy(csound);

// same rules as parse_opcode_list in src/resolve_pulgins.rs
const opcodes = new Map();
for (const entry of entries) {
    // internal variants are named like poscil3.a: the command line lists them as poscil3
    const name = entry.opname.split('.')[0];
    if (!OPCODE_NAME.test(name)) { continue; }
    // the command line prints (null) for no outputs or inputs
    const signature = [entry.outypes || '(null)', entry.intypes || '(null)'];
    const signatures = opcodes.get(name) ?? [];
    if (!signatures.some(([o, i]) => o === signature[0] && i === signature[1])) {
        signatures.push(signature);
    }
    opcodes.set(name, signatures);
}

// Csound encodes its version as major * 1000 + minor * 10 + patch
const generatedWith = `Csound ${Math.floor(version / 1000)}.${Math.floor(version / 10) % 100}.${version % 10}`;
// one opcode per line, so that a new Csound release gives a readable diff
const lines = [...opcodes.keys()].sort().map(name => `  ${JSON.stringify(name)}: ${JSON.stringify(opcodes.get(name))}`);
const text = `{\n "generated_with": ${JSON.stringify(generatedWith)},\n "opcodes": {\n${lines.join(',\n')}\n }\n}\n`;
JSON.parse(text);  // stays valid JSON
writeFileSync(output, text);
console.log(`${output}: ${opcodes.size} opcodes from ${generatedWith}`);
