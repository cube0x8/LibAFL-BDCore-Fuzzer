# LibAFL Fuzzer for BDEngine

This repository contains a fuzzer targeting the Bitdefender antivirus engine.
It uses the [BDClient](https://github.com/cube0x8/BDClient) harness as its target.
For more information about the fuzzer design and a high-level overview of its
internals, read [Fuzzing the Bitdefender Engine](https://stackbits.eu/blog/vulnerability_research_bitdefender_engine_part_2.html).

## How to build

Clone [LibAFL](https://github.com/AFLplusplus/LibAFL) and
[PEMutator](https://github.com/cube0x8/PEMutator) next to this repository:

```text
parent/
  LibAFL/
  PEMutator/
  LibAFL-BDCore-Fuzzer/
```

The Bitdefender engine package must contain `bdcore.dll` and a directory named
`Plugins`. Pass either an engine archive or an extracted engine directory to
the build task:

```sh
cargo install cargo-make
cargo make build -- --engine /path/to/engine.zip
```

An extracted engine directory can be used instead:

```sh
cargo make build -- --engine /path/to/extracted-engine
```

If LLVM is not detected automatically, set `LLVM_CONFIG_PATH`, for example:

```sh
LLVM_CONFIG_PATH=/usr/bin/llvm-config-18 cargo make build -- --engine /path/to/engine.zip
```

## How to run a fuzzing campaign

The following command runs the standard `ScanFile` harness. With no focused
target switch, each testcase from `corpus/` is passed to the snapshotted
`ScanFile` execution:

```sh
./target/release/qemu_bdclient \
  --input corpus \
  --queue queue \
  --output crashes \
  --sync-dir sync \
  --timeout 20000 \
  --cores 0-7 \
  --modules cevakrnl.xmd \
  -- ./target/bdclient/bdclient_x64 \
  --root-system-dir ./target/bdclient \
  ./target/bdclient/dummy/input_file
```

`--modules` restricts coverage collection to a comma-separated list of engine
modules. Run `./target/release/qemu_bdclient --help` for focused unpacker
targets, mutator options, QASAN cores, and DrCov replay options.
