# Releasing `superred` to PyPI

This project publishes to [PyPI](https://pypi.org) automatically whenever you
publish a **GitHub Release**. You never run `twine upload` by hand and you never
store an API token: a GitHub Actions workflow builds the package and uploads it,
authenticating to PyPI with short-lived OpenID Connect (OIDC) credentials
("Trusted Publishing").

There are two parts:

1. **One-time setup** (done once, below). Establishes the trust link between this
   GitHub repository and the PyPI project.
2. **Cutting a release** (repeated for every version). Bump the version, publish a
   GitHub Release, done.

---

## How versioning works

The version lives in exactly one place:

```python
# src/superred/__init__.py
__version__ = "0.1.0"
```

`pyproject.toml` reads it from there (`[tool.hatch.version]`), so the built
package always carries that number. The release workflow additionally checks
that the **Git tag of the release equals `__version__`**, and refuses to publish
on a mismatch. So the rule is simply:

> The release tag is `v<__version__>`. Tag `v0.1.0` requires `__version__ = "0.1.0"`.

PyPI does not allow re-uploading a version that already exists. Every release
needs a new, higher version number ([semantic versioning](https://semver.org):
`MAJOR.MINOR.PATCH`).

---

## One-time setup

### 1. Create a PyPI account

Register at <https://pypi.org/account/register/> and verify your email. For the
optional dry-run rehearsals, also register the separate account at
<https://test.pypi.org/account/register/>.

### 2. Tell PyPI to trust this repository

Because the `superred` project does not exist on PyPI yet, you register a
**"pending" trusted publisher**. It creates the project on the first successful
upload.

Go to <https://pypi.org/manage/account/publishing/> and add a new pending
publisher with exactly these values:

| Field                    | Value        |
| ------------------------ | ------------ |
| PyPI Project Name        | `superred`   |
| Owner                    | `RoldSI`     |
| Repository name          | `superred`   |
| Workflow name            | `release.yml`|
| Environment name         | `pypi`       |

(Optional, for TestPyPI dry runs: repeat the same at
<https://test.pypi.org/manage/account/publishing/> but with Environment name
`testpypi`.)

### 3. Create the GitHub environments

In the GitHub repo: **Settings -> Environments -> New environment**, create one
named `pypi` (and, if you want dry runs, one named `testpypi`). These names must
match step 2. You can optionally add a required reviewer to `pypi` so a release
upload waits for a manual click, which is a good safety gate.

That is the whole setup. You never touch it again unless the repo or workflow
file is renamed.

---

## Cutting a release

### 1. Bump the version

Edit `src/superred/__init__.py` and raise `__version__` (for example `0.1.0` ->
`0.1.1`). Commit it to `main` (through a PR, as usual).

### 2. Publish a GitHub Release

On GitHub: **Releases -> Draft a new release**.

- **Choose a tag**: type `v<version>` (for example `v0.1.1`) and pick "Create new
  tag on publish". The leading `v` is expected; the workflow strips it.
- **Target**: `main` (the commit that carries the matching `__version__`).
- Write release notes, then click **Publish release**.

Publishing the release triggers `.github/workflows/release.yml`, which:

1. Builds the source distribution and wheel.
2. Fails loudly if the tag does not match `__version__`.
3. Runs `twine check` on the metadata.
4. Uploads to PyPI via Trusted Publishing.

Watch it under the repo's **Actions** tab. When it goes green, the package is
live at <https://pypi.org/project/superred/> and installable with:

```bash
pip install superred
```

---

## Optional: rehearse on TestPyPI first

Before your very first real release you can exercise the entire pipeline without
touching real PyPI:

1. Complete the TestPyPI trusted-publisher and environment setup (the optional
   lines in steps 2 and 3 above).
2. Go to **Actions -> Release -> Run workflow**, leave "Dry run" checked, and run
   it. It builds and uploads to <https://test.pypi.org/project/superred/>.

TestPyPI is a throwaway sandbox; its contents are periodically wiped and it is
not a place to leave a real release.

---

## Troubleshooting

- **"Version does not match tag"**: `__version__` and the release tag disagree.
  Fix `__version__` on `main`, delete the release and its tag, and re-publish.
- **"File already exists" from PyPI**: that version was already uploaded. Bump to
  a new version; you cannot overwrite or re-upload an existing one.
- **"invalid-publisher" / OIDC error**: the trusted-publisher entry on PyPI does
  not match. Recheck owner `RoldSI`, repo `superred`, workflow `release.yml`, and
  environment `pypi` for typos.
