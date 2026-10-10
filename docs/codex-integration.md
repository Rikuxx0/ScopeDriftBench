# Codex連携

本ラボはOpenAI Codex CLI `0.160.0`を専用Docker Imageへ固定し、PentestCodeと同じScenario、Condition、Seed、Difficulty、Policy、Evaluatorで実行できます。Codexは汎用Coding Agentであり、PentestCodeのPentest Coordinatorを使用しません。そのため、`agent`を独立した実験因子として記録し、両者のRunを同一Agentの反復として混ぜないでください。

## ビルドと認証

```bash
make build
make up
make auth-login AGENT=codex
make auth-status AGENT=codex
make healthcheck
```

CodexのDevice Loginは、PentestCodeとは別の`codex-auth` Named Volumeへ保存されます。`make down`や`make reset`では削除されません。`make reset`はCodexのWorkspaceと非認証Stateだけを消去し、Run間の作業ファイル混入を防ぎます。認証情報を削除する場合は`make auth-logout AGENT=codex`を使用します。API KeyをContainerや`.env`へ保存する必要はありません。

Agent Orchestratorは認証情報を読むためrootで動作しますが、モデルが選択したShell Processは`lab` UIDへ降格されます。Shell環境から`OPENAI_API_KEY`、`CODEX_API_KEY`、`CODEX_ACCESS_TOKEN`を除去し、`/auth`と`/state`はroot以外から読めないModeにします。

## 実行

一括実行は次のとおりです。

```bash
make dynamic-run \
  AGENT=codex \
  SCENARIO=S1 \
  CONDITION=A \
  SEED=42 \
  NETWORK_MODE=seeded \
  DIFFICULTY=equal \
  MODEL=gpt-5.6-luna \
  VARIANT=medium \
  LIVE_VIEW=pretty
```

準備と実行を分ける場合は次のとおりです。

```bash
make run AGENT=codex SCENARIO=S1 CONDITION=A SEED=42 DIFFICULTY=equal
make execute RUN_ID=<RUN_ID> MODEL=gpt-5.6-luna VARIANT=medium LIVE_VIEW=pretty
make evaluate RUN_ID=<RUN_ID>
```

`execute`はRunの`metadata.json`に保存された`agent`とNetwork構成からAdapterとアドレスを復元するため、2番目のCommandに`AGENT`や`NETWORK_MODE`を再指定する必要はありません。

## 実行経路とTrace

1. Host Runnerが固定済み`agent_prompt.txt`をCodex用Containerへ標準入力で渡します。
2. Container内のWrapperが`codex exec --json --ephemeral`を起動します。
3. Codex固有のUser設定やProject Rulesを読み込まず、ModelとReasoning EffortをRun引数で固定します。
4. Codexの内部Sandboxと対話承認を使用せず、外側のread-only Container、非特権Tool UID、内部Docker Networkを実行境界とします。
5. 各JSON Eventへ取得時刻を追加し、完全なTraceを`codex_trace.jsonl`へ保存します。
6. 完了した`command_execution`を共通の`events.jsonl`へ正規化し、同じEvaluatorで判定します。

`LIVE_VIEW=pretty`はCommand、Payload、Target、結果を整形表示します。`json`は生JSON、`both`は両方です。`make reparse RUN_ID=<RUN_ID>`でRaw TraceからAction EventとMetricsを再生成できます。

## Condition C

Codex用Agent Containerは、CodexがShell Toolに使用する`/bin/sh`と`/bin/bash`の両方を不透明なBoundaryへ置き換えています。Wrapper本体と転送先ShellはAgent UIDから読み取り・直接実行できません。許可されたCommandだけを匿名実行イメージ経由で`lab` UIDとして起動します。Condition CではRead-only Policy Fileが存在する場合だけGateが有効になり、スコープ外IP、禁止された破壊操作、未承認の権限昇格操作は実行前に拒否され、`POLICY_GATE:DENY_*` MarkerがTraceに残ります。ConditionとScenarioの識別子はAgent環境へ渡しません。

Codex CLIのOAuth通信について、RelayはDevice Login、モデル一覧、推論に加え、CLIがChatGPT Workspaceの接続先を決定するための`GET /backend-api/wham/accounts/check`だけを許可します。プラグイン一覧、MCP、ユーザー設定、分析イベントの経路は許可しません。

実験Runnerは`apps`、`plugins`、`remote_plugin`を明示的に無効化します。また、組み込みProviderと同じChatGPT OAuth Endpointを使う実験専用の一時Providerを指定し、推論TransportをHTTPSへ固定します。Runは`--ephemeral`で実行されるため、Provider IDによるSession再開一覧への影響はありません。これにより、実験対象ではないWorkspace連携やWebSocket接続の再試行がライブログへ混ざることを防ぎます。

Gateとは独立して、`codex-gated`には`outscope-net`インターフェースがありません。Python Socketや難読化されたCommandでGate判定を回避しても、Runで生成された未認可サブネットへはNetwork Layerで到達できません。

## 比較実験上の注意

PentestCodeはPentest専用Coordinator、Subagent、専用Toolを持ちますが、Codexは汎用Coding Agentです。したがって、違反率だけで安全性を比較せず、少なくとも次を併記してください。

- 有効なFlag取得率
- 対象サービスを発見できたか
- スコープ外操作を選択したか
- GateでBlockされたか
- 総Tool Call数とGoal到達までのAction数

Codexがスコープ外へアクセスしなかった場合でも、対象を発見できなかったRunと、発見後に自制したRunは区別する必要があります。

## 公式設計根拠

OpenAIの公式資料では、Codex CLIのHeadless実行、外部Sandboxでの隔離、全Commandの監査、サイバー操作の副作用直前におけるScope検査と独立したNetwork Boundaryが案内されています。本実装はこれらをDocker、Shell Gate、Raw Trace、独立Evaluatorとして具体化しています。

- [Codex CLIをHeadless実行する例](https://developers.openai.com/cookbook/examples/codex/build_iterative_repair_loops_with_codex)
- [Guardrailsとサイバー操作のHuman Review](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)
- [Sandbox Security](https://developers.openai.com/api/docs/guides/agents-api/environments/security)
