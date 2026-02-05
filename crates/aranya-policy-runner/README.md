# Aranya Policy Runner

The Aranya Policy Runner is a simple tool that can run sequences of
actions on policy files. It prints their effects.

## Usage

```
Usage: policy-runner [OPTIONS] <POLICY> [RUNS]...

Arguments:
  <POLICY>   The policy file to load
  [RUNS]...  The run files to load

Options:
  -w, --working-directory <WORKING_DIRECTORY>
          The working directory for all data stored
  -d, --deterministic-rng <DETERMINISTIC_RNG>
          Use a deterministic RNG with the given seed (NOT YET IMPLEMENTED)
      --marker
          Add a marker to the output when execution moves to a new run file
  -q, --quiet
          Suppress trace output and other diagnostics
      --validator
          Run the validator on the policy compilation (NOT YET IMPLEMENTED)
  -h, --help
          Print help
```

## Examples

A simple policy is included under `examples`, along side several run
files which initialize and manipulate the graph. If you are in the
`aranya-policy-runner` directory, you can replace `policy-runner` with
`cargo run --`.

### Initialize a graph

This creates a new graph. Your working directory should be empty, as the
runtime will enforce that the first command in the graph is has `Init`
priority.

```
$ policy-runner -w wd examples/policy.md examples/init
TeamCreated { owner_dev: H4oPsseLyQAE1g9PWzSUiUy7BnbZcPJ8QVKgijgahx1h }
UserAdded { dev: AY5b9qh2sKpdD55L242RR4CCpVoEDJ6NhUA73dw4x19q }
```

### Run a command on an initialized graph

This and the following example require the graph to be initialized. This
example just sends a simple command that contains a message.

```
$ policy-runner -w wd examples/policy.md examples/hello
Message { msg: "Hello from test runner" }
```

### Set a fact value and retrieve it

These two examples set a Device fact and then retrieve it. They cannot
be run together since they define the same global data in the preamble.

```
$ policy-runner -w wd examples/policy.md examples/add_raw_device
UserAdded { dev: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN }
```

```
$ policy-runner -w wd examples/policy.md examples/get_raw_device
DeviceInfo { device_id: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN, device_key: b:AA55AA55AA55AA55 }
```

### Execute multiple run files with separation marker

This executes the first three examples in one go. As this adds the
`Init` command, you must clear your working directory (`wd` here) before
running this.

```
$ policy-runner --marker -w wd examples/policy.md examples/{init,hello,add_raw_device}
--- examples/init
TeamCreated { owner_dev: 5Bq1Ctuurk28WLkm7PtLwgZwJut8Lcfoqja5CEYMeg46 }
UserAdded { dev: Bd2s5eMHnCRUKHni1usWLmkD9ntny98GYAc4Rcp9zTpo }
--- examples/hello
Message { msg: "Hello from test runner" }
--- examples/add_raw_device
UserAdded { dev: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN }
```