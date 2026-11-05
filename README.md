# Csound Language Server

A Language Server Protocol (LSP) implementation for [Csound](https://csound.com), written in Rust and built on the [Csound Tree-sitter grammar](https://github.com/PasqualeMainolfi/tree-sitter-csound).
It brings editor support for `.csd`, `.orc`, `.sco` and `.udo` files to any LSP client: VS Code, Zed, Neovim, Helix and others.

The server targets Csound 7, including its new syntax: typed variables, user-defined types (`struct`), modern UDO signatures, `for` loops and array slices.

## Features

- **Diagnostics**: syntax errors, unknown opcodes and `<CsOptions>` flags, unclosed `instr`/`opcode`/control blocks, missing score p-fields, UDO signature mismatches, unused and undefined variables.
- **Completion**: opcodes (with their signatures), variables in scope, user-defined opcodes and types, struct members after `.`, types after `:`, macros, and `<CsOptions>` flags.
- **Hover**: the Csound manual page of an opcode, plugin documentation, and the definition of user-defined opcodes and types.
- **Semantic highlighting**, including embedded languages (HTML, Python, JSON, TOML) inside a `.csd`.
- **Included files**: opcodes and types defined in `#include`d files are known in the including file.
- **Formatting**: indentation while typing.
- **Code lenses** to run the file, stop it, and open the manual.

## Opcodes, plugins and user-defined types

The server learns what exists from the Csound installed on your system, so plugins are recognised like built-in opcodes:

- At startup it runs `csound --list-opcodes1 --list-structs`. Every opcode Csound can load is known, even without a manual page (e.g. `printfi`), and completion shows its signatures.
- Types registered by plugins (`csound --list-structs`) get hover and member completion like the ones written in your files.
- Plugins loaded with `--opcode-lib=` or `--opcode-dir=` are included when these flags appear in the `<CsOptions>` of an open file, in the editor settings (see below), or in `.csound7rc`. The list is refreshed when a file is opened or saved, or when the settings change.
- Plugin documentation comes from the [Risset](https://github.com/csound-plugins/risset-data) index and from [csound/plugins](https://github.com/csound/plugins).

When Csound can't be run (not installed, or not on the editor's `PATH`), the server uses the last list it got from your Csound, and otherwise a list of the opcodes of the latest Csound release embedded at build time.

Listing plugin types and libraries given with `--opcode-lib` requires a recent Csound 7. With older versions the server still works, without those.

## Installation

Download the binary for your platform from the [Releases](https://github.com/PasqualeMainolfi/csound-lsp/releases) page and put it somewhere in your `PATH`, or build it from source with a recent Rust toolchain:

```bash
git clone https://github.com/PasqualeMainolfi/csound-lsp.git
cd csound-lsp
cargo install --path .
```

`cargo build --release` also works: then move `target/release/csound-lsp` to a folder in your `PATH`.

The Csound manual used for hover is downloaded on first start and cached in the system temporary folder.

## Editor setup

- **VS Code**: the [Csound extension](https://marketplace.visualstudio.com/items?itemName=kunstmusik.csound-vscode-plugin) downloads and updates the server for you. It also runs in the browser (vscode.dev), with a web version of the server.
- **Zed**: use the [Csound Zed Support](https://github.com/PasqualeMainolfi/csound-zed) extension, which starts `csound-lsp`.
- **Other editors**: start the `csound-lsp` executable over stdio for Csound files. For example, in Neovim 0.11+ (which has no Csound filetype of its own):

```lua
vim.filetype.add({ extension = { csd = "csound", orc = "csound", sco = "csound", udo = "csound" } })

vim.lsp.config("csound_lsp", {
  cmd = { "csound-lsp" },
  filetypes = { "csound" },
  init_options = {
    csound = { executable = "csound", playArgs = { "--opcode-lib=/path/to/libmyplugin.dylib" } },
  },
})
vim.lsp.enable("csound_lsp")
```

## Configuration

Settings are read from `initializationOptions` and from `workspace/didChangeConfiguration`, both shaped as:

```json
{
  "csound": {
    "executable": "csound",
    "playArgs": ["-odac", "--opcode-lib=/path/to/libmyplugin.dylib"]
  }
}
```

| Setting | Default | Description |
| --- | --- | --- |
| `csound.executable` | `"csound"` | The Csound executable the server asks for its opcodes and types. |
| `csound.playArgs` | `[]` | The arguments you run Csound with. Only `--opcode-lib=` and `--opcode-dir=` are used, to list the opcodes and types of those plugins. Use absolute paths here; relative paths in `<CsOptions>` are resolved from the file's folder. |

The VS Code extension sends its own `csound.executable` and `csound.playArgs` settings.

## Development

```bash
cargo test
```

`resources/csound_opcodes.json` is the list embedded as the last resort. The release workflow regenerates it from the latest [`@csound/browser`](https://www.npmjs.com/package/@csound/browser) before building:

```bash
npm install --no-save --no-package-lock @csound/browser@latest
node scripts/list_csound_opcodes.mjs
```

## Status

The project is under active development: features may change, and feedback and bug reports are welcome in the [issues](https://github.com/PasqualeMainolfi/csound-lsp/issues).
