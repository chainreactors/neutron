# harness

`cmd/harness` is a local verification tool for xray-to-neutron conversion. It
builds mock HTTP services from xray POC semantics, runs the converted neutron
template against those services, and reports whether the converted template can
still hit an xray-positive scenario.

## Usage

Verify one POC:

```powershell
go run ./cmd/harness verify -i bin\xray-original\poc\5ea116c4-224c-476e-99e0-7e099c1bcc2b.yml
```

Verify the full xray POC directory:

```powershell
go run ./cmd/harness verify -i bin\xray-original\poc -workers 8 -fail-only
```

Emit JSON and per-request traces for debugging:

```powershell
go run ./cmd/harness verify -i bin\xray-original\poc\example.yml -json -debug
```

Serve generated mock scenarios manually:

```powershell
go run ./cmd/harness serve -i bin\xray-original\poc\example.yml -listen 127.0.0.1:7788
```

Options:

- `-i`: xray POC file or directory.
- `-workers`: number of parallel verification workers for `verify`.
- `-fail-only`: only print non-OK files in text output.
- `-json`: print a structured verification report.
- `-debug`: include per-request neutron execution traces.
- `-max-delay`: maximum modeled response delay. Defaults to the harness limit.
- `-listen`: listen address for `serve`.

## Report Status

- `ok`: the converted neutron template matched at least one generated
  xray-positive scenario.
- `divergent`: harness generated an xray-positive scenario, but the converted
  neutron template did not match it.
- `unsupported`: harness could not generate a supported scenario for this POC.
- `convert_error`: xray-to-neutron conversion failed.
- `compile_error`: converted neutron YAML could not compile.
- `execute_error`: converted template execution failed against the mock server.

For the current xray corpus, non-OOB cases should be held to `divergent=0`.
Known reverse/OOB callback templates are intentionally surfaced separately as
`convert_error` until neutron has an equivalent callback model.

## Mechanism

The harness does not try to replay real vulnerable products. Instead, it creates
minimal positive HTTP scenarios from the xray template itself:

1. Load xray POC YAML.
2. Parse the top-level rule expression and select runnable rule sets.
3. Seed variables from `set`, payloads, request path/header/body placeholders,
   and expression hints.
4. Build route matchers for each xray request.
5. Mutate mock responses so the original xray rule expression evaluates true.
6. Apply xray `output` extraction to produce runtime variables for later rules.
7. Convert the same POC to neutron.
8. Compile and execute the converted neutron template against the generated
   mock HTTP server.
9. Mark the file `ok` only if neutron matches an xray-positive scenario.

This catches cases where conversion succeeds syntactically but the converted
template cannot actually reproduce the xray detection flow.

## Mock HTTP Details

Route matching is generated from xray request data:

- Static paths are matched literally.
- `{{variable}}` placeholders become either concrete values or wildcard capture
  groups.
- Captured request variables are fed back into response generation.
- Headers and bodies are matched with generated regular expressions.
- Response literals can render `{{variable}}` placeholders.
- Request chains preserve extracted dynamic values, such as a first response
  extracting a path used by a later request.

Response generation is expression-driven:

- `response.status == N` sets the mock status code.
- `contains`, `bcontains`, `starts_with`, `ends_with`, and `regex` add matching
  body/header/title content.
- Latency comparisons generate bounded response delays.
- Common xray set-variable chains are inferred, including `base64`, URL
  encoding, `hex`, `bytes`, `string`, `md5`, concat expressions, and
  `bformat(16, 0, "", 0)`.
- Payload-driven requests are executed with sequential request-condition
  indexes, so converted expressions such as `body_1`, `body_2`, ... can be
  validated.

## Debugging Divergence

Use `-json -debug` on one file:

```powershell
go run ./cmd/harness verify -i bin\xray-original\poc\example.yml -json -debug
```

The debug report includes each neutron HTTP event:

- request URL and serialized request
- status code, headers, body, latency, matched URL
- request-condition history fields such as `body_1` and `status_code_2`
- extracted dynamic values
- whether that event matched

When a case is `divergent`, compare the generated response and extracted
variables with the converted neutron matchers. Prefer fixing conversion or
harness modeling first. Only change neutron runtime semantics when the behavior
is already compatible with nuclei/neutron expectations.

## Current Boundaries

The harness is meant for high-signal equivalence testing, not as a complete xray
runtime implementation. Current boundaries:

- Reverse/OOB callback semantics are not modeled.
- Some top-level non-rule expressions and negative-only flows may be unsupported.
- Delay modeling is bounded by `-max-delay`.
- Mock responses are minimal positive samples, not full product emulations.

Despite those limits, every supported generated scenario should be a meaningful
xray-positive case. A `divergent` result should be treated as a real conversion
or harness modeling bug until proven otherwise.
