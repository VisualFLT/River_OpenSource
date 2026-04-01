# RiverServer OLLVM Usage

This document describes the two obfuscating LLVM toolchains currently present in `RiverServer` and how they are used.

## Toolchains

### 1. Old toolchain: `C:\llvm\ollvm-16`

This is the older OLLVM-style toolchain already used by some existing projects in `RiverServer`.

Current references:

- `C:\Users\Marqu\Desktop\River0.6\RiverServer\leechagent\ollvm-16.build.props`
- `C:\Users\Marqu\Desktop\River0.6\RiverServer\leechcore\ollvm-16.build.props`

Those props files currently point to:

```xml
<LLVMInstallDir>C:\llvm\ollvm-16</LLVMInstallDir>
```

The old projects using this pattern rely on `PlatformToolset=ClangCL` and inject the LLVM path through `ExecutablePath`.

Typical old parameter styles already present in this repository:

- `-mllvm -sub`
- `-mllvm -split`
- `-mllvm -fla`
- `-mllvm -bcf`

There are also some `irobf-*` style options in `leechagent` and `leechcore`, for example:

- `-mllvm -irobf-cie`
- `-mllvm -irobf-cfe`
- `-mllvm -irobf-icall`
- `-mllvm -irobf-indgv`
- `-mllvm -irobf-fla`

These options belong to the old toolchain layout and should not be assumed to exist in the new toolchain.

### 2. Current toolchain: `C:\llvm\llvm_kernel\llvm-msvc-ex-2026-3-4-install`

This is the current toolchain we validated and compiled successfully against.

Current active use:

- `C:\Users\Marqu\Desktop\River0.6\RiverServer\RiverServerSingleDll.vcxproj`

This project uses `PlatformToolset=ClangCL`, but overrides the actual binaries through project properties:

- `LLVMInstallDir`
- `CLToolExe`
- `CLToolPath`
- `LinkToolExe`
- `LinkToolPath`
- `LibToolExe`
- `LibToolPath`

Important detail:

Visual Studio's `ClangCL` rules expected `lib\clang\16`, but this toolchain ships with `lib\clang\777`. To make the IDE/toolchain work together, a compatibility directory was added:

- `C:\llvm\llvm_kernel\llvm-msvc-ex-2026-3-4-install\lib\clang\16`

This mirrors the current toolchain's include resource layout so VS `ClangCL` rules do not fail.

## Active configuration in RiverServerSingleDll

File:

- `C:\Users\Marqu\Desktop\River0.6\RiverServer\RiverServerSingleDll.vcxproj`

Current active LLVM install directory:

```text
C:\llvm\llvm_kernel\llvm-msvc-ex-2026-3-4-install
```

The project keeps a switch:

```text
UseCustomLlvmKernel
```

Behavior:

- default: use the current custom `llvm-msvc-ex`
- if `UseCustomLlvmKernel=false`: fall back to normal VS/MSVC behavior

## Current "maximum stable" obfuscation parameters

The current parameter set that was verified to build successfully for `RiverServerSingleDll.vcxproj` is:

```text
-Wno-incompatible-function-pointer-types
-mllvm -fla
-mllvm -sub
-mllvm -sub_loop=1
-mllvm -split
-mllvm -split_num=3
-mllvm -bcf
-mllvm -bcf_loop=1
-mllvm -bcf_prob=40
-mllvm -string-obfus
-mllvm -const-obfus
-mllvm -ind-call
```

In short:

- `fla`: control-flow flattening
- `sub`: instruction substitution
- `sub_loop=1`: one extra substitution round
- `split`: basic block splitting
- `split_num=3`: stronger split level
- `bcf`: bogus control flow
- `bcf_loop=1`: one extra bogus-flow round
- `bcf_prob=40`: bogus-flow insertion probability
- `string-obfus`: string obfuscation
- `const-obfus`: constant obfuscation
- `ind-call`: indirect call transformation

This set is intentionally aggressive and will noticeably increase build time and output size.

## Practical recommendation

Use the old `C:\llvm\ollvm-16` only for projects that are already wired to its props files and older parameter style.

Use the new `C:\llvm\llvm_kernel\llvm-msvc-ex-2026-3-4-install` for new RiverServer work, especially if you want:

- the newer validated toolchain
- `string-obfus`
- `const-obfus`
- `ind-call`
- a project-local override model instead of relying on a fragile custom VS platform toolset

## How to switch RiverServerSingleDll

### Use the current custom obfuscating LLVM

Build normally:

```powershell
msbuild C:\Users\Marqu\Desktop\River0.6\RiverServer\RiverServerSingleDll.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Force normal compiler instead of the custom LLVM

```powershell
msbuild C:\Users\Marqu\Desktop\River0.6\RiverServer\RiverServerSingleDll.vcxproj /p:Configuration=Release /p:Platform=x64 /p:UseCustomLlvmKernel=false
```

## Current output

Last validated output path for the new toolchain:

```text
C:\Users\Marqu\Desktop\River0.6\RiverServer\files\single_dll\x64\RiverServerSingleDll.dll
```
