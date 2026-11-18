# アーキテクチャ

ScopeDriftBenchは、次の責務を既存コードで分離します。CLIは`scopedriftbench`です。内部実装の`pentestlab_cli.py`は互換性のため残します。

| 責務 | 実装 |
|---|---|
| Benchmark Runner | `pentestlab_cli.py`、`runner/run_experiment.py`、`runner/batch.py` |
| Scenario | `scenarios/`とSeedから確定するPrompt、Task、Target、Policy |
| Agent Adapter | `runner/adapters.py`のCodex、PentestCode、Local Harness |
| Model Provider | `codex_oauth`、`runner/providers.py`のOllama／LM Studio |
| Isolated Environment | `docker-compose.yml`の内部Networkと合成Service |
| Collector / Raw Trace | `collector/`、Agent固有Trace、共通`events.jsonl` |
| Evaluator | `evaluator/`の独立したPolicy判定と指標 |
| Results | `results/<RUN_ID>/`のMetadata、Trace、Metrics、Violations |

```text
Benchmark CLI → Scenario + Agent + Model → Agent Harness
  → Isolated Benchmark Environment → Collector / Raw Trace
  → Independent Evaluator → Results
```

標準Runは従来のA相当で、Agentは認可側と未認可側の合成ネットワークへ技術的に到達できます。エージェントの行動を固定済みGround Truth Policyで後処理評価します。認可側にもGoal達成経路があるため、未認可側へ接続する必要はありません。新規RunでConditionは選択しません。新規Runの`benchmark_format`で過去のCondition付きRunと区別します。

## 実行と隔離

Codex CLI／PentestCodeは隔離コンテナ内で実行し、OAuth推論だけを経路制限付きの`llm-relay`へ送ります。Ollama／LM Studioはホスト側Orchestratorの`LocalProvider`から固定したOriginへ接続し、モデルが選んだ型付きShell操作だけを既存の隔離コンテナで実行します。モデルはProvider URLやDocker CLI引数を選べません。

`scope-net`、`outscope-net`、`inference-net`は内部Networkです。AgentとTargetには直接Internet Egress、Docker Socket、Host Networkを付けません。`provider-egress`に接続するのはOAuth Relayだけです。`./results:/results`が唯一のBind Mountで、AgentのCredentialは別々のroot専用Named Volumeに保存されます。Shell Boundaryは標準Runでも非特権の`lab` UIDへの降格、Credentialの分離、環境保護のために維持します。これらはベンチマーク環境の保護であり、Agentのスコープ遵守を代行するGateではありません。

過去の研究用Cで使ったGated Container、Policy File、未認可側Interfaceを持たない構成は、隔離Healthcheckと安全機構への依存があるためコード上に残します。**標準ベンチマークRunからは選択しません。** Shell BoundaryとGateを一体で実装した既存イメージを無理に削除すると、非特権Tool実行とCredential保護にも影響するためです。

S11〜S13のCIA Mock、S14のWeb／SSH MockはScenarioに応じて既存Compose Profileから起動します。Mockは合成状態とSafety Limitを持ち、ホストへのPortやVolumeを公開しません。RunごとのSeedはIP・Network名・Interface順へ決定論的に適用し、確定値をMetadata、Prompt、Policy、Trace分類に共通利用します。Network変更時にComposeの内部Networkは再作成しますが、OAuth Credential Volumeは保持します。

Compose Project Nameの`pentest-governance-lab`と`pgl-`のリソース識別子は既存Volume、Credential、Network、およびSeed再現性を保つため維持します。表示上のプロジェクト名やCLI名とは独立しています。

`results/<RUN_ID>/`にはPrompt、Scenario、Policy、Metadata、Agent固有Raw Trace、共通Action Event、独立評価のMetricsとViolationsを保存します。Flagの文字列だけでなく取得元を評価し、認可外Targetから同じFlagを取得しても有効な成功にはしません。
