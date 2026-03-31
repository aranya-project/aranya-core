# Aranya Policy Runner

The Aranya Policy Runner is a command-line tool that runs sequences of
actions on policy files and prints their effects. It is meant to be a
basic tool for iteratively building a policy while providing quick,
repeatable feedback.

## Usage

```text
policy-runner [OPTIONS] <POLICY> [RUNS]...
```

At its most basic, you must specify a policy document and one or more
["run files"](#run-files). The run files specify the actions and command
that are run on the policy. As effects are committed, they are printed
to the output. For more information, see the command's help output
(`policy-runner --help`).

### Run Files

A run file has two parts, a "preamble" which allows the definition of
values, and a "do" section which lists the actions and raw command
structs to run against the policy. As the actions and commands are
executed, effects are printed to the configured output (`stdout` by
default, or the file specified by `-o`).

For more information on how run files work, see the `runfile` module
documentation.

## Examples

A simple policy is included under `examples` alongside several run
files which initialize and manipulate the graph. If you are in the
`aranya-policy-runner` directory, you can use `cargo run --` isntead of
`policy-runner` in the following examples.

### Initialize a graph

This creates a new graph. We specify the working directory here (`-w
wd`) so we can persist state across the following examples. The working
directory should be empty, as the runtime will enforce that a command
with `Init` priority can only be added to an empty graph.

```text
$ policy-runner -w wd examples/policy.md examples/init.run
TeamCreated { owner_dev: H4oPsseLyQAE1g9PWzSUiUy7BnbZcPJ8QVKgijgahx1h }
UserAdded { dev: AY5b9qh2sKpdD55L242RR4CCpVoEDJ6NhUA73dw4x19q }
```

### Run a command on an initialized graph

This and the following two examples require the graph to be initialized
by the prior [Initialize a graph](#initialize-a-graph) section. This
example just creates a simple command that contains a message.

```text
$ policy-runner -w wd examples/policy.md examples/hello.run
Message { msg: "Hello from test runner" }
```

### Set a fact value and retrieve it

These two examples set a Device fact and then retrieve it.

```text
$ policy-runner -w wd examples/policy.md examples/add_raw_device.run
UserAdded { dev: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN }
```

```text
$ policy-runner -w wd examples/policy.md examples/get_raw_device.run
DeviceInfo { device_id: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN, device_key: b:AA55AA55AA55AA55 }
```

### Fail to retrieve a device

This example tries to retrieve a device with a random ID. Unless you're
exceedingly lucky, this device shouldn't be found and it produces an
error effect.

```text
$ policy-runner -w wd examples/policy.md examples/get_raw_device_not_found.run
DeviceNotFound { device_id: BRJpYqJh3ZSdCtmB4XkXQvPCwQdANmDaeASvgGtTxk9X }
```

### Execute multiple run files with separation marker

This executes all of the above examples in one go. We do not specify the
working directory, so this runs independently in a temporary directory
that is removed after execution.

```text
$ policy-runner --marker examples/policy.md examples/{init,hello,add_raw_device, get_raw_device}.run
--- examples/init.run
TeamCreated { owner_dev: 6V1zpGgX16S3UkzHZ1QYfWak9XpkxVg12DaYUwZTWB9M }
UserAdded { dev: 54MPYg3vo9seBBpaQw6rwP6dU4SnkFkaw7fy8t8eurvE }
--- examples/hello.run
Message { msg: "Hello from test runner" }
--- examples/add_raw_device.run
UserAdded { dev: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN }
--- examples/get_raw_device.run
DeviceInfo { device_id: 111thX6LZfHDZZKUs92fh1cxwDCA3ZJ3RGvuRPy5sAQN, device_key: b:AA55AA55AA55AA55 }
```