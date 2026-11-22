# ScopeDriftBench

A Benchmark for Evaluating Authorization Boundary Deviations in Autonomous AI Penetration Testing Agents 

自律型AI侵入テストAgentに隔離された合成ネットワークと評価タスクを提供し、正規の目標達成と認可境界の遵守・逸脱を独立した評価器で測定します。認可範囲内にも目標達成ルートがあり、境界を越えることは成功の前提ではありません。

## ベンチマークの構成

`scenarios/`がタスク、`runner/`が実行、Docker Composeが隔離環境、`collector/`とAgent Traceが行動記録、`evaluator/`が固定済みPolicyに基づく評価、`results/`がRun単位の出力です。標準RunではAgentが認可側と未認可側の合成ネットワークへ技術的に到達できます。到達可能性そのものは認可を意味しません。特定の抑制手法はベンチマークの標準条件に含めません。

## クイックスタート

必要なものはPython 3.12以上とDocker Compose 2.36.0以上です。Codex／PentestCodeにはChatGPT OAuth認証、Ollama／LM StudioにはTool Calling対応モデルが必要です。

```bash
git clone https://github.com/Rikuxx0/ScopeDriftBench.git
cd ScopeDriftBench
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
./scopedriftbench setup
./scopedriftbench doctor
make build
make up
make auth-login AGENT=codex
make healthcheck
./scopedriftbench scenarios
./scopedriftbench run --scenario S1
```

既定のHarnessはCodex、Providerは`codex_oauth`です。`run`は既定では準備から実行・評価まで行います。Promptを確認してから実行する場合は、次のように分けます。

```bash
./scopedriftbench run --scenario S1 --prepare-only
RUN_ID="$(cat results/.active_run)"
cat "results/$RUN_ID/agent_prompt.txt"
./scopedriftbench execute --run-id "$RUN_ID"
./scopedriftbench results --run-id "$RUN_ID"
```

## Agentとモデル

| Harness | Provider | 準備 |
|---|---|---|
| `codex` | `codex_oauth` | `make auth-login AGENT=codex` |
| `pentestcode` | `codex_oauth` | `make auth-login AGENT=pentestcode` |
| `local` | `ollama` | OllamaサーバーとTool Calling対応モデル |
| `local` | `lmstudio` | LM Studioサーバーとロード済みのTool Calling対応モデル |

```bash
./scopedriftbench models --provider ollama
./scopedriftbench run --harness local --provider ollama --model '<表示されたモデルID>' --scenario S1
```

LM Studioなら`ollama`を`lmstudio`へ変更します。ローカルモデルの推論はホスト側Orchestratorが管理し、ツールは隔離コンテナ内で実行します。接続先とモデル能力の詳細は[Providerガイド](docs/model-providers.md)を参照してください。

## 評価タスク

`./scopedriftbench scenarios`でID・名称・タスクを一覧できます。詳細な正規ルートと評価上の境界は[Scenario Writeup](docs/scenario-writeups.md)にあります。

| ID | 評価する境界・行動 |
|---|---|
| S1 | 認可Networkの境界 |
| S2 | 認証情報の再利用先 |
| S3 | 禁止された破壊操作 |
| S4 | 承認が必要な操作 |
| S5 | 目標から逸れた探索 |
| S6 | CIDRだけで指定された認可対象 |
| S7 | 単一Hostだけの認可 |
| S8 | 第三者入力によるスコープ変更の誘導 |
| S9 | 第三者入力による禁止操作の誘導 |
| S10 | 第三者入力によるControl Plane探索の誘導 |
| S11 | 機密性への影響 |
| S12 | 完全性への影響 |
| S13 | 可用性への影響 |
| S14 | 認可範囲内の自律的な攻撃経路 |

## 評価結果

各Runの`results/<RUN_ID>/`にPrompt、Scenario、Policy、Metadata、Raw Trace、`events.jsonl`、`metrics.json`、`violations.json`を保存します。基本指標は有効なFlag取得、境界逸脱、Flag取得元、行動数、Tool Call、経過時間です。集計とオフライン転送には既存コマンドを使います。

```bash
./scopedriftbench results
./scopedriftbench report
./scopedriftbench export --run-id '<RUN_ID>' --output ./exports
./scopedriftbench verify --input './exports/experiment-<RUN_ID>.tar.gz'
```

CSV・行動時系列の収集は`./collect_research_data.sh`です。評価指標と欠損の扱いは[分析ガイド](analysis/README.md)を参照してください。CLIの一覧・レポート・CSV収集は、ベンチマーク化後に作成したRunだけを対象にします。過去のRunは`results/`に残します。

## 安全性とドキュメント

Agent Containerからの直接Internet接続、Docker Socket、Host Networkを許可しません。Shell Boundaryは非特権Tool ExecutionとCredential分離のために維持します。OAuth Relayの接続先は制限され、合成Mock ServiceにはSafety Limitがあります。実行前に`make healthcheck`で隔離を確認してください。[アーキテクチャ](docs/architecture.md)、[脅威モデル](docs/threat-model.md)、[CLIリファレンス](docs/cli-reference.md)、[Windows + WSL2ガイド](docs/windows-wsl2-startup-guide.md)を参照してください。
