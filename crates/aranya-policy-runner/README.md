# Aranya Policy Runner

The Aranya Policy Runner is a simple tool that can run sequences of
actions on policy files and print their effects.

## Usage

```text
policy-runner [OPTIONS] <POLICY> [RUNS]...

Arguments:
  <POLICY>   The policy file
  [RUNS]...  One or more run files

Options:
  -w, --working-directory <WORKING_DIRECTORY>  The working directory for all data stored
      --deterministic-rng                      Use a deterministic RNG
      --marker                                 Add a marker to the output between run files
  -q, --quiet                                  Suppress trace output and other diagnostics
      --validator                              Run the validator on the policy compilation
  -h, --help                                   Print help (see more with '--help')
```

## Examples

A simple policy is included under `examples` along side several run
files which initialize and manipulate the graph. If you are in the
`aranya-policy-runner` directory, you can use `cargo run --` isntead of
`policy-runner` in the following examples.

### Initialize a graph

This creates a new graph.  We specify the working directory here (`-w
wd`) so we can persist state across the following examples. The working
directory should be empty, as the runtime will enforce that a command
with `Init` priority can only be added to an empty graph.

```text
$ policy-runner -w wd examples/policy.md examples/init
TeamCreated { owner_dev: H4oPsseLyQAE1g9PWzSUiUy7BnbZcPJ8QVKgijgahx1h }
UserAdded { dev: AY5b9qh2sKpdD55L242RR4CCpVoEDJ6NhUA73dw4x19q }
```

### Run a command on an initialized graph

This and the following example require the graph to be initialized by
the prior [Initialize a graph](#initialize-a-graph) section. This
example just creates a simple command that contains a message.

```text
$ policy-runner -w wd examples/policy.md examples/hello
Message { msg: "Hello from test runner" }
```

### Set a fact value and retrieve it

These two examples set a Device fact and then retrieve it. They cannot
be run together since they define the same global data in the preamble.

```text
$ policy-runner -w wd examples/policy.md examples/add_raw_device
UserAdded { dev: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN }
```

```text
$ policy-runner -w wd examples/policy.md examples/get_raw_device
DeviceInfo { device_id: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN, device_key: b:AA55AA55AA55AA55 }
```

### Execute multiple run files with separation marker

This executes the first three examples in one go. We do not specify the
working directory, so this runs independently in a temporary directory
that is removed after execution.

```text
$ policy-runner --marker examples/policy.md examples/{init,hello,add_raw_device}
--- examples/init
TeamCreated { owner_dev: 5Bq1Ctuurk28WLkm7PtLwgZwJut8Lcfoqja5CEYMeg46 }
UserAdded { dev: Bd2s5eMHnCRUKHni1usWLmkD9ntny98GYAc4Rcp9zTpo }
--- examples/hello
Message { msg: "Hello from test runner" }
--- examples/add_raw_device
UserAdded { dev: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN }
```