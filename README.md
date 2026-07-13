# CTF Trace Validator

A small web app that lets users validate a **CTF 1.8.x** (Common Trace Format)
trace by uploading it and running the relevant **Babeltrace 2** commands against
it. The app shows the exact success or error output `babeltrace2` produced.

## What it runs

A CTF trace is a *directory* containing a `metadata` file (TSDL) plus its binary
stream files. On upload, the server writes the files to a temporary trace
directory, finds the one containing `metadata`, and runs three checks
([babeltrace2 docs](https://babeltrace.org/docs/v2.0/man1/babeltrace2.1/)):

| Check | Command | What it proves |
|-------|---------|----------------|
| Metadata validation | `babeltrace2 query src.ctf.fs metadata-info --params 'path="DIR"'` | The TSDL metadata parses. Invalid metadata errors here. |
| Trace structure | `babeltrace2 query src.ctf.fs babeltrace.trace-infos --params 'inputs=["DIR"]'` | Stream files are consistent with the metadata. |
| Full read | `babeltrace2 -i ctf DIR` | Events decode end to end. |

Each result shows the command, exit code, stdout, and stderr. Per the man page,
babeltrace2 exits `0` on success and `1` otherwise.

## Requirements

- **Node.js** (18+)
- **Babeltrace 2** installed and on `PATH` (or point `BABELTRACE2` at the binary).
  If it isn't found, the app still runs and clearly reports each check as
  *unavailable* instead of failing silently.

## Run

```sh
npm install
npm start          # http://localhost:3000
```

Environment variables:

- `PORT` — server port (default `3000`)
- `BABELTRACE2` — path to the `babeltrace2` executable (default: `babeltrace2` on PATH)

## Uploading

Provide the trace's `metadata` file together with its stream files, drop a whole
trace folder ("pick a folder"), or upload a single `.zip` of the trace
directory. The upload must contain a file literally named `metadata`.
