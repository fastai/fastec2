## fastec2

AWS EC2 computer management for regular folks...

## Installation

```bash
$ pip install git+https://github.com/fastai/fastec2.git
```

To add tab completion for your shell (replace *bash* with *fish* if you use the fish shell, although note as at Feb-2019 there are reports fish completions may be broken in the Google Fire library that this relies on):

```bash
$ fe2 -- --completion bash > ~/.fe2-completion
$ echo 'source ~/.fe2-completion' >> ~/.bashrc
$ source ~/.bashrc
```

## Usage

For a list of commands, type:

```bash
$ fe2

Usage:       fe2 -
             fe2 - change-type
             fe2 - connect
             fe2 - get-ami
             fe2 - get-price-hist
             ...
```

Each command can provide help, as follows:

```bash
$ fe2 change-type -- --help

Usage:       fe2 change-type NAME INSTTYPE
             fe2 change-type --name NAME --insttype INSTTYPE
```

An [introduction and guide](https://www.fast.ai/2019/02/15/fastec2/) is available for the command line API and REPL. See the `examples` directory for examples of the Python API.
