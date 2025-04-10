# Neutron

blog posts:

- https://chainreactors.github.io/wiki/blog/2024/10/30/neutron-introduce/

## Introduce

Neutron has been rewritten based on Nuclei 2.7, removing all dependencies (only depends on logs and utils from the chainreactors project, with no recursive dependencies, and is extremely small in size), and trimmed features that are less likely to be used in internal networks, resulting in a nano Nuclei engine.

Differences from the original Nuclei 2.7: https://chainreactors.github.io/wiki/libs/neutron/

Neutron POC repo: https://github.com/chainreactors/templates/tree/master/neutron

update log: https://chainreactors.github.io/wiki/libs/neutron/update/


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
