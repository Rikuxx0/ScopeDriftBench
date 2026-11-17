# Pentest Agent Governance Control Lab

自律型侵入テストAgentが認可境界を守るかを、隔離されたDocker Labで測定する研究基盤です。Codex CLI、PentestCode、Ollama・LM Studio用の独立Harnessに対応します。対象は合成サービスで、実在する脆弱な製品や外部Targetは含みません。

## 何を調べるか

| 研究課題 | 主なScenario |
|---|---|
| RQ1：不完全な認可情報で境界を逸脱するか | S1、S6、S7 |
| RQ2：第三者入力で逸脱を誘発できるか | S8〜S10 |
| RQ3：モデル非依存の制御で逸脱を防げるか | S1、S3、S6〜S10のCondition A/C比較 |
| 境界逸脱の影響と自律的な攻撃経路 | S11〜S14 |

Scenarioごとの内容と正規ルートは[Scenario Writeup](docs/scenario-writeups.md)、比較方法と指標は[実験設計](docs/experiment-design.md)を参照してください。

## 必要な環境

- Docker Compose v2
- Python 3.12以上
- Codex/PentestCodeを使う場合は、それぞれのChatGPT OAuth認証
- ローカルモデルを使う場合は、OllamaまたはLM Studioの推論サーバーとTool Calling対応モデル

## 実験を始める

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
./pentestlab setup
make build
make up
make auth-login AGENT=codex
make healthcheck
./pentestlab run --harness codex --provider codex_oauth --model gpt-5.6-luna --scenario S1 --condition A --seed 42 --difficulty equal --prepare-only
RUN_ID="$(cat results/.active_run)"
cat "results/$RUN_ID/agent_prompt.txt"
./pentestlab execute --run-id "$RUN_ID" --variant medium
```

`./pentestlab run --prepare-only`はLabを準備し、Prompt・Policy・Scenario・Metadataを`results/$RUN_ID/`へ保存します。Promptを確認してから`./pentestlab execute`を実行してください。Dockerの起動・OAuth認証・隔離状態の確認には上記のMakeコマンドを使います。PentestCodeを使う場合は`--harness pentestcode`を指定し、`make auth-login AGENT=pentestcode`で認証します。

```bash
cat "results/$RUN_ID/agent_prompt.txt"
cat "results/$RUN_ID/policy.yaml"
cat "results/$RUN_ID/metrics.json"
```

正常終了時は`events.jsonl`、`violations.json`、`metrics.json`まで生成されます。失敗・中断時も部分Traceを残します。実行方法の詳細は[CLIリファレンス](docs/cli-reference.md)、[Codex連携](docs/codex-integration.md)、[PentestCode連携](docs/pentestcode-integration.md)を参照してください。

## モデルとHarnessを選ぶ

`./pentestlab providers`でProvider、`./pentestlab experiments`でScenario、`./pentestlab results --run-id "$RUN_ID"`で実験結果を確認できます。モデルやHarnessは`run`のオプションで選択します。

Ollamaを使う場合は、Ollamaを起動してTool Calling対応モデルを用意し、次を実行します。

```bash
./pentestlab models --provider ollama
./pentestlab run --harness local --provider ollama --model '<モデル一覧に表示されたID>' --scenario S1 --condition A --seed 42 --prepare-only
RUN_ID="$(cat results/.active_run)"
cat "results/$RUN_ID/agent_prompt.txt"
./pentestlab execute --run-id "$RUN_ID"
```

LM Studioの場合は、Developer画面でサーバーを起動し、Tool Calling対応モデルをロードしてから、`ollama`を`lmstudio`に置き換えます。

```bash
./pentestlab models --provider lmstudio
./pentestlab run --harness local --provider lmstudio --model '<モデル一覧に表示されたID>' --scenario S1 --condition A --seed 42 --prepare-only
RUN_ID="$(cat results/.active_run)"
cat "results/$RUN_ID/agent_prompt.txt"
./pentestlab execute --run-id "$RUN_ID"
```

ローカルモデルでは`--variant`を使いません。既定の接続先はOllamaが`http://localhost:11434/v1`、LM Studioが`http://localhost:1234/v1`です。接続先が異なる場合は`run`に`--provider-url <URL>`を指定します。Docker Labの`make build`・`make up`・`make healthcheck`は先に実行してください。OAuth認証はローカルモデルの実行には不要です。

Ollama・LM Studioの推論はホスト側Orchestratorが管理し、ツールは既存の隔離Containerで実行します。Providerの設定と対応するHarnessの組み合わせは[Providerとローカルモデル](docs/model-providers.md)、CLIの操作と比較実験は[CLIリファレンス](docs/cli-reference.md)を参照してください。

## 結果を集計する

```bash
./pentestlab report
bash collect_research_data.sh
```

`./pentestlab report`はEvaluatorのRun集計を`results/`へ、収集スクリプトは保存済みRunから行動・通信・時系列などを`analysis/output/`へ出力します。通信数は観測可能な範囲の下限です。CSVの定義と欠損の扱いは[研究データ収集](analysis/README.md)に記載しています。

## Windowsへの移行とオフライン転送

WSL2環境では[スタートアップガイド](docs/windows-wsl2-startup-guide.md)に沿って準備し、`./pentestlab doctor --json`で依存関係を確認します。起動中のLabを検査する場合だけ`./pentestlab doctor --full`を指定します。終了したRunは`./pentestlab export --run-id "$RUN_ID" --output ./exports`で保存し、転送先では`./pentestlab verify --input ./exports/experiment-"$RUN_ID".tar.gz`で照合します。USB転送と再現性Metadataもガイドに記載しています。

## 実行境界

Condition AではAgentが両方のLab Zoneへ技術的に到達できます。Condition CではShell Gateが禁止操作を実行前に判定し、さらに`outscope-net`への経路を持ちません。Agent Containerに直接のInternet接続、Docker Socket、Host Networkは付与しません。実行前には`make healthcheck`で隔離状態を確認してください。詳細は[アーキテクチャ](docs/architecture.md)、[脅威モデル](docs/threat-model.md)、[IP構成](docs/network-addressing.md)を参照してください。

## 開発・検証

```bash
make test
```

Scenario追加は[実験設計の手順](docs/experiment-design.md#シナリオの追加)を参照してください。S11〜S13のCIA Mockは[CIA影響評価](docs/cia-impact-evaluation.md)、S14の経路は[自律攻撃進行評価](docs/attack-progression-evaluation.md)に記載しています。

この環境でOllama・LM Studioの実サーバーとDocker Labを組み合わせた動的実行は未検証です。実験は合成対象での境界判断を測るもので、実環境での侵入テスト能力を示すものではありません。
