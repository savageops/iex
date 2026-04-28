# IX Developer Inspection Command Surface

IX includes read-only code inspection primitives beside search so agents can replace shell-specific file-reading fragments with one native command family. The search engine remains the canonical hit-discovery owner.

## Command Taxonomy

```text
ix search <expr> [PATH]...      // full search report and summary
ix matches <expr> [PATH]...     // hit records only, same search engine
ix inspect <PATH>... [bounds]   // read-only file windows
ix inspect --expr <expr> ...    // search-backed match context
ix explain <expr>               // expression plan JSON
```

`ix inspect` is read-only. Replacement, write, in-place editing, shell execution, PowerShell delegation, and sed delegation are outside this surface. A future transform command can own mutation with a separate preview/apply contract.

## Shell Workflow Mapping

```text
Get-Content file -TotalCount 40
ix inspect file --total-count 40

Get-Content file | Select-Object -Skip 120 -First 30
ix inspect file --skip 120 --limit 30

sed -n '40,80p' file
ix inspect file --range 40:80

Select-String -Path src -Pattern SearchConfig -Context 2
ix inspect --expr 'lit:SearchConfig' src --context 2

Select-String -Path src -Pattern 'TODO|FIXME' -Context 1 | ConvertTo-Json
ix inspect --expr 're:TODO|FIXME' src --context 1 --json
```

## Output Shape

Human file windows emit stable line records:

```text
path:line:text
```

Match context emits role-tagged records:

```text
path:line:match:text
path:line:context:text
```

JSON file windows emit:

```json
{
  "reports": [
    {
      "path": "src/main.rs",
      "requested": {
        "start_line": 1,
        "end_line": null,
        "skip": 0,
        "limit": 40,
        "allow_full": false
      },
      "total_emitted_lines": 40,
      "lines": [{ "line": 1, "text": "..." }]
    }
  ]
}
```

JSON match context emits:

```json
{
  "expression": "lit:SearchConfig",
  "reports": [
    {
      "path": "src/main.rs",
      "lines": [{ "line": 10, "role": "match", "text": "..." }]
    }
  ]
}
```

## Ownership

- `crates/iex-core/src/inspect.rs` owns bounded UTF-8 file-window extraction.
- `crates/iex-cli/src/inspect.rs` owns inspection grammar and rendering.
- `crates/iex-cli/src/search.rs` owns both `search` and `matches`, with `matches` reusing the same `run_search` path.
- `crates/iex-cli/src/compat.rs` owns rg-style ingress lowering.
- `crates/iex-cli/src/main.rs` owns only command enumeration and dispatch.
