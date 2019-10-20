# Contributing

- Code is structured as a core package with public API and CLI tool.
- All Python dependencies, installation, and tests are managed by
  `setup.py`.
- CLI tool uses standard exit codes and additional defined as the same
  Enum.
- Warnings are enabled and forwarded to logs.
- Git workflow is simplified [GitFlow](https://nvie.com/posts/a-successful-git-branching-model/)
  without release branches. When a feature is finished in its *feature*
  branch, its author creates pull request to the `dev` branch. Branches
  `dev` and `master` are protected and require pull request review. The
  author should request 2 other team members for a code review. Branch 
  `master` contains only *production-ready* state.

## Development Guidelines

- All code merged to `dev` has unit tests and documentation.
- New code is according to [PEP8](https://www.python.org/dev/peps/pep-0008/).
- Document code with docstrings. If reasonable, include examples in
  docstrings and use [`doctest`](https://docs.python.org/3/library/doctest.html).
  Documentation can be parsed from docstrings.
- Use [context managers](https://docs.python.org/3/library/stdtypes.html#typecontextmanager)
  for cleanup actions.
- Use [`typing`](https://docs.python.org/3/library/typing.html) where
  specific type is expected.
- Log events with various levels using [`logging`](https://docs.python.org/3/library/logging.html),
  but **don't** log
  any sensitive information. Every module has its logger.
- CLI tool has tests.

- Use Python's virtual environment for development.
- Don't use `*` in an import statement.
- Comparison of sensitive data (string/bytes) should be done in constant
  time to prevent timing attacks.
