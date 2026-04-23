# LIBAFL Fuzzer for BDEngine
This fuzzer targets the Linux-port ([bdclient](https://github.com/cube0x8/BDClient)) of the BitDefender anti-virus core system using QEMU as emulation engine.

## BitDefender core
The Windows Bitdefender core is composed of a DLL, `bdcore.dll`, and a directory named `Plugins` containing packed and encrypted plugins for various parsing and scanning tasks.

To obtain it, we suggest installing Bitdefender Antivirus and then creating a zip archive that contains:

- `bdcore.dll`
- the plugin directory, making sure it is named `Plugins`

This zip archive is the engine package you will pass to the build command.

## Build and run the fuzzer
To build the fuzzer with the selected Bitdefender core, pass the zip created above with `--engine`. The `--engine` value can be:

- an online URL starting with `https://`
- a local path to the zip archive
- a local path to an already extracted engine directory

To build and run a fuzzing session:
```
$ cargo make build -- --engine $URL_TO_BDCLIENT_ENGINE_ZIP
$ cargo make build -- --engine https://example.com/engine.zip
# or use a local path
$ cargo make build -- --engine /path/to/engine.zip
$ cargo make build -- --engine /path/to/extracted-engine/
$ cargo run --release -- --input corpus/ --output crashes/ --timeout 20000 --sync-dir sync/ --cores n-n+x --modules pdf.xmd -- ./target/bdclient/bdclient_x64 --root-system-dir ./target/bdclient/ ./target/bdclient/dummy/input_file
```

### Using PEMutator
To use the PE format-aware mutator, clone [PEMutator](https://github.com/cube0x8/PEMutator) next to this repository so the local layout matches the dependency path used by this project:

```
$ cd ..
$ git clone https://github.com/cube0x8/PEMutator
```

Then build the fuzzer as usual with `cargo make build -- --engine ...` and enable the mutator at runtime with `--pe-mutator`.

Available CLI switches for configuring `PEMutator`:

- `--pe-mutator`: enable the PE format-aware mutator
- `--pe-mutator-reporting`: write PE mutator reporting to `/tmp/pe-report.txt`
- `--pe-min-stack-depth <N>`: minimum number of stacked PE mutations per pass
- `--pe-max-stack-depth <N>`: maximum number of stacked PE mutations per pass
- `--pe-header`: enable only PE header mutations
- `--sections`: enable only section mutations
- `--assembly`: enable only assembly mutations
- `--export-dir`: enable only export directory mutations
- `--resource-dir`: enable only resource directory mutations
- `--data-dir`: enable only data directory entry mutations

Example:

```
$ cargo run --release -- --pe-mutator --pe-min-stack-depth 3 --pe-max-stack-depth 6 --sections --assembly --input corpus/ --output crashes/ --timeout 20000 --sync-dir sync/ --cores n-n+x --modules pdf.xmd -- ./target/bdclient/bdclient_x64 --root-system-dir ./target/bdclient/ ./target/bdclient/dummy/input_file
```

## Custom coverage filters
Use `--modules` to restrict coverage instrumentation to specific Bitdefender modules instead of instrumenting everything loaded by the engine. Pass a comma-separated list of module names, for example:

```
$ cargo run --release -- --input corpus/ --output crashes/ --modules pdf.xmd,archive.xmd -- ./target/bdclient/bdclient_x64 --root-system-dir ./target/bdclient/ ./target/bdclient/dummy/input_file
```

If `--modules` is omitted, the fuzzer instruments all available modules.

## Custom exit points
The fuzzer snapshots execution state at the beginning of `ScanFile` in the bdclient harness, then restores that snapshot between testcases so fuzzing can restart from the same scanning entry point.

With `--exit-point`, you can provide custom `module:+offset` addresses where execution should stop and the snapshot should be restored early, which is useful when you want to focus fuzzing on a specific region past `ScanFile` setup or avoid running the full path to the default return point.

## Prometheus
The fuzzer will push execution statistics to a prometheus server specified by the argument `--prometheus-addr`:
```
cargo run --release -- fuzz [..] --prometheus-addr 127.0.0.1:31337 -- ./target/x86_64/bdclient/bdclient_x64 --root-system-dir ./target/x86_64/bdclient/ /tmp/input_file
```

Make sure you have a -- properly configured -- prometheus server:
```
# Install prometheus server
$ sudo apt install prometheus
```
Modify the prometheus.yml file by adding the following lines under the `scrape_configs` section:
```
file_sd_configs:
    - files:
        - /path/to/fuzzers_targets.json
```
Prometheus will load the target dynamically from `/etc/prometheus/fuzzer_targets.json`, and the Fuzztron Web Panel will write that file everytime a new fuzzer is created.
But, if you want to test if a fuzzer is correctly pushing metrics and read them from the prometheus web interface, add the following target to the `fuzzer_targets.json` file:
```
[
  {
    "targets": ["localhost:31337"],
    "labels": {
      "job": "fuzzer"
    }
  }
]
```
Remember that the targets must be contained between the first array (`[]`). So if you want to add a second one:
```
[
  {
    "targets": ["localhost:31337"],
    "labels": {
      "job": "fuzztron_prometheus",
      "instance": "localhost:31337"
    }
  },
  {
    "targets": ["localhost:31338"],
    "labels": {
      "job": "fuzztron_prometheus",
      "instance": "localhost:31338"
    }
  }
]

```
Start the prometheus service:

```
$ systemctl start prometheus
```

To test prometheus and check if the fuzzer is correctly pushing the metrics, you can navigate to `http://localhost:9090` and perform the following query:
```
{instance="localhost:31337"}
```
