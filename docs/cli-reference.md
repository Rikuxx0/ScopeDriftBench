# `scopedriftbench` CLI

標準ベンチマークRunではConditionを選びません。既存のA相当の隔離環境を使用します。新規Runには`benchmark_format`を記録し、識別子のない過去のRunはCLIの一覧・レポート・CSV収集から除外します。設定ファイルは`.scopedriftbench.yaml`です。既存の`.pentestlab.yaml`も読み込み、`experiment.condition`があれば新規Runでは無視します。

| コマンド | 内容 |
|---|---|
| `setup` | `.scopedriftbench.yaml`と仮想環境のCLIリンクを準備。旧設定がある場合は引き続き利用 |
| `doctor [--full] [--json]` | OS、Docker、GPU、Providerを診断。`--full`は稼働中LabのHealthcheckも実行 |
| `scenarios` | Scenario ID、名称、タスクを一覧表示 |
| `models --provider ollama\|lmstudio` | モデル一覧と公開される能力を表示 |
| `providers` | Providerと接続先を表示 |
| `config` | 現在の設定を表示。`set-provider`と`set-model`で変更可能 |
| `run [--scenario ID]` | Scenarioの準備、Agent実行、評価 |
| `run --prepare-only` | Prompt・Policy・Metadataを準備し、実行を待つ |
| `execute --run-id ID` | 準備済みRunを実行・評価 |
| `results [--run-id ID]` | Run一覧または個別結果 |
| `report` | EvaluatorのCSV集計を生成 |
| `compare` | 保存済みの標準Runをモデル／Harness別に比較。`--execute`で既存Batch Runnerから実行 |
| `export --run-id ID\|--all --output DIR` | Runをtar.gzとChecksumへ保存 |
| `verify --input ARCHIVE [--json]` | 展開せずManifestとSHA-256を照合 |

`experiments`は旧CLIの`scenarios`別名として残しています。`run`を引数なしで対話端末から呼ぶと、Harness、Provider、Model、Scenarioを選びます。Seed、Network Mode、Difficulty、推論設定は希望するときだけ詳細設定で変更します。`--scenario`などを指定すると非対話で実行します。ローカルHarnessでは`--variant`を使わず、OAuth HarnessではTemperatureやMax Output Tokensを指定しません。

`run`には`--harness`、`--provider`、`--model`、`--scenario`、`--seed`、`--network-mode`、`--difficulty`、`--authorization-profile`、`--live-view`などを指定できます。`--provider-url`はローカルProviderのRunに適用します。`models`と`doctor`の接続先は`.scopedriftbench.yaml`の`providers.<名前>.base_url`で設定してください。`--prepare-only`で止めたRunは、Prompt確認後に`execute`で起動します。

```bash
./scopedriftbench scenarios
./scopedriftbench run --scenario S1 --prepare-only
RUN_ID="$(cat results/.active_run)"
./scopedriftbench execute --run-id "$RUN_ID"
./scopedriftbench results --run-id "$RUN_ID"
```

`execute`は準備時のMetadataからHarness・Provider・Model・Network構成を復元します。結果は`results/<RUN_ID>/`に保存します。ProviderやHarnessの組み合わせは[Providerガイド](model-providers.md)、隔離構成は[アーキテクチャ](architecture.md)を参照してください。

`compare`はベンチマークRunからScenario、Network Mode、Seed、Harness、Modelが一致するものを選びます。過去のCondition付きRunは比較に含めません。モデルとHarnessは同時に変更せず、比較対象を明示します。HTTPリクエスト数は観測可能な下限であり、Tool Call数とは別です。
