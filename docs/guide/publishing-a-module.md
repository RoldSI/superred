---
layout: doc
title: "Publishing a Module"
permalink: /guide/publishing-a-module
---

# Publishing a Module

Once you have written a [target](/guide/writing-a-target), an
[optimizer](/guide/writing-an-optimizer), or a [claim](/guide/writing-tasks),
package it as a standalone, pip-installable module so other people can install it
and run it against their own systems.

## Package layout

Each target, optimizer, and claim is its own pip-installable package. The layout
is uniform across the repo:

```
my_optimizer/
  pyproject.toml
  src/my_optimizer/
    __init__.py        # public exports
    optimizer.py       # implementation
  tests/
```

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "my-optimizer"          # pip name: dashes
version = "0.1.0"
dependencies = ["superred"]

[tool.hatch.build.targets.wheel]
packages = ["src/my_optimizer"]   # import name: underscores
```

```bash
pip install -e ./my_optimizer
```

```python
from my_optimizer import MyOptimizer   # import by the underscore name
```

The pip name uses dashes (`my-optimizer`) and the import name uses underscores
(`my_optimizer`); the folder under `superred-modules/` may differ again (the
`test_*` fixtures are a deliberate example). Export your public surface from
`__init__.py`, including any security-domain tag constants callers need to build
scopes (the targets export their `*_TAG` constants for exactly this).

## Get it listed

Once your module is published, we would appreciate a note to
[info@simonsure.com](mailto:info@simonsure.com) so we can add it to the
[modules directory](/modules) for other people to find and use.
