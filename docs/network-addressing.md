# IPアドレス構成

本ラボは、従来の固定アドレスとSeed連動アドレスの2モードを提供します。

## Fixed Mode

`NETWORK_MODE=fixed`は既存Runとの互換モードです。明示的に指定した場合、次のサブネットを使用します。

- `scope-net`: `10.10.1.0/24`
- `outscope-net`: `10.10.2.0/24`
- `inference-net`: `10.10.3.0/24`

## Seeded Mode

`NETWORK_MODE=seeded`が既定値です。SHA-256を使ってSeedから3つの重複しない`10.0.0.0/8`内の`/24`と、各サービスの重複しないHost Addressを生成します。同じSeedと実装Versionからは常に同じ結果が得られます。`make run`や`make dynamic-run`では指定を省略できます。

```bash
make up NETWORK_MODE=seeded SEED=42
make dynamic-run \
  AGENT=codex \
  SCENARIO=S1 \
  CONDITION=A \
  SEED=42 \
  NETWORK_MODE=seeded \
  DIFFICULTY=equal \
  MODEL=gpt-5.6-terra \
  VARIANT=low \
  LIVE_VIEW=pretty
```

`make dynamic-run`または`make run`だけでも、現在のラボと要求された構成が異なる場合はContainerと内部Networkを自動再作成します。Named Volumeは削除されないため、PentestCodeとCodexのOAuth認証は保持されます。

生成された現在の構成は`.generated/network.json`、Compose向け変数は`.generated/network.env`へ保存されます。この2ファイルは生成物でありGit管理されません。実験ごとの確定値は次にも保存されます。

- `results/<RUN_ID>/metadata.json`の`network_mode`と`network`
- `results/<RUN_ID>/scenario.yaml`のTargetとNetwork
- `results/<RUN_ID>/policy.yaml`の認可・禁止Network
- `results/<RUN_ID>/agent_prompt.txt`の実際のTargetとScope

準備と実行を分けた場合、`make execute RUN_ID=<RUN_ID>`は保存済み構成を再適用します。別SeedのRunを直前に実行していても、評価対象のIPとPolicyは混在しません。

## 比較実験での扱い

A/B/Cを比較するときは、同じSeedとNetwork Modeを使用してください。SeedごとにIPを変えることで固定IPへの暗記や過学習の影響を減らせますが、Conditionごとに別のIPを使うとネットワーク構成自体が交絡要因になります。

完全な非決定的ランダム値は使用しません。再現不能なアドレスを採用すると、Trace、Policy、Gate判定、再実行結果の検証が困難になるためです。
