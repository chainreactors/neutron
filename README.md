# Neutron

blog posts:

- https://chainreactors.github.io/wiki/blog/2024/10/30/neutron-introduce/

## Introduce

Neutron has been rewritten based on Nuclei 2.7, removing all dependencies (only depends on logs and utils from the chainreactors project, with no recursive dependencies, and is extremely small in size), and trimmed features that are less likely to be used in internal networks, resulting in a nano Nuclei engine.

Differences from the original Nuclei 2.7: https://chainreactors.github.io/wiki/libs/neutron/

Neutron POC repo: https://github.com/chainreactors/templates/tree/master/neutron

update log: https://chainreactors.github.io/wiki/libs/neutron/update/

## Nuclei compatibility boundaries

Neutron intentionally tracks nuclei behavior only where it affects template
semantics. CyberHub-specific runtime extensions are documented separately so
they are not mistaken for upstream nuclei behavior.

| Area | Neutron behavior | Upstream nuclei v3 behavior | Boundary |
| --- | --- | --- | --- |
| Cookie jar | `NewScanContext` creates one jar per scan and HTTP requests clone the compiled client with that jar unless `disable-cookie` is set. | `contextargs.Context.CookieJar` is shared by HTTP templates in one workflow/execution. | Compatible. TinyGo returns nil because browser/WASM fetch owns cookies. |
| Redirects | `RedirectPolicy` plus `makeCheckRedirectFunc` implements no-follow, follow-all, and same-host redirects. | `httpclientpool.RedirectFlow` implements the same redirect choices. | Compatible by behavior and names; enum numeric values are not a persistence/API contract. |
| HTTP client reuse | Per-scan cookie jars are attached via a client clone, so jar state is isolated per execution. | `httpclientpool` skips adding clients to the pool when a cookie jar is present. | Compatible for jar-backed executions. Neutron does not need to mirror nuclei's full pool. |
| Charset normalization | Core HTTP response decoding handles content encodings only (`gzip`, `deflate`). | Nuclei does not normalize legacy HTML charsets in the HTTP engine. | CyberHub extension. Legacy charset normalization belongs in the caller-provided transport layer. |
| Favicon data | Converted xray icon-content rules are emitted as explicit `/favicon.ico` requests and hash the response body in DSL (`mmh3(base64_py(body))`). Runtime favicon fields are derived from the current response only. | Nuclei templates request favicon URLs explicitly and calculate hashes through DSL helpers. | Compatible direction. Neutron no longer performs hidden favicon discovery/fetching in the HTTP engine. |


### CMD

neutron 提供了两个简单的测试工具, 帮助用户测试poc

### validate

指定poc路径, 加载并预编译指定路径下的所有poc

```bash
go run ./cmd/validate <path_or_file>
```

### shot

指定poc路径和url, 对单个url

```bash
go run ./cmd/shot [-proxy <proxy_address>] <path_or_file> <target_url> 
```
