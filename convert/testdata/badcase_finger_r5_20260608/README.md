# Bad-case 指纹用例集(r5 实跑回归基线,2026-06-08)

## 这是什么

2026-06-08 SDK v0.2.4 在 1655 个抓取目标上跑 `batch_compare`(r5 全量实跑),发现下面 22 件 xray 指纹 YAML 在转换 → 执行链路上漏检明显。这个目录把 **原始 xray YAML + r5 时刻每个产品的实测 URL 列表 + 当时 SDK 的命中结果** 一起入库,作为 converter/executer 改动的回归基线。

## 文件清单

```
urls.tsv                              219 行,字段:yaml_file\tproduct\turl\tr5_sdk_match\tr5_sdk_fingerprints
<product>.yaml                        21 件 xray 指纹 YAML,从 reports/focus-validate/xray_fingers.tgz 中拆出
```

YAML 文件是 **xray 格式**(`name: fingerprint-<vendor>--<product>` + `detail.fingerprint.name`),不是转换后的 nuclei 模板。`Convert(yaml) → templates.Template → tmpl.Execute(url)` 这条链在测试里现场跑。

## r5 实测概要(命中数 / 目标数)

| 文件 | 产品 | r5 实测 | 备注 |
|---|---|---|---|
| aisite.yaml | 中科汇联-AiSite | 0/20 | r5 全 0,根因疑似 dir() 或 favicon hash 规则丢失 |
| weaver_e_office.yaml | 泛微-EOffice | 0/10 | redirects:false + contains(location,...) 漏检 |
| weblogic.yaml | WebLogic-Server | 0/10 | version_in_header + AND→OR 转换器丢规则 |
| sslvpn_4.yaml | Array-SSL-VPN | 0/10 | |
| iam.yaml | 竹云-IAM | 0/10 | 末块超时丢已有 result |
| goahead.yaml | Embedthis GoAhead | 0/10 | |
| haiyun.yaml | 拓尔思-政府网站集约化 | 0/10 | |
| empirecms.yaml | 帝国CMS | 8/10 | 已基本追平 debug |
| wcm.yaml | 拓尔思-WCM | 6/10 | |
| erds.yaml | 讯投-ERDS | 10/10 | r5 已经命中 |
| 其它 | 详见 urls.tsv |  | |

完整逐行命中明细在 `urls.tsv` 第 4 列(`True`/`False` = r5 当时 SDK 的 sdk_match)。

## 怎么用

`convert/badcase_finger_test.go` 里的 `TestBadCaseFinger_R5Targets` 会:
1. 把 testdata 下所有 `*.yaml` 用 `Convert` 转换;
2. 对每个 URL 跑一次 `tmpl.Execute(url)`;
3. 输出当前命中率,和 `urls.tsv` 里的 r5 基线做对比。

默认 `go test -short` 跳过网络部分,只验 Convert + Compile 不 panic。要复跑实测加 `-run BadCaseFinger -timeout 30m`。

## 不在这里固化的事

- 不固化"漏检的产品必须漏检"——这只是回归基线,不是期望。
- 不锁定具体目标可达性——`urls.tsv` 里若干 URL 几个月后必然失活,失活按 r5 时刻数据为准,不影响测试通过。

## 关联

- [[project_finger_ci_yaml_followups_20260608]](memory)
- [[project_sdk_v024_equivalence_and_finger_conversion_gap_20260608]](memory)
- [[project_sdk_v024_finger_gap_redirects_false]](memory)
