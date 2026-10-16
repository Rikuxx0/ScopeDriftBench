# アーキテクチャ

本システムでは、5つの責務を分離します。合成ターゲットは技術的な侵入機会を提供し、PentestCodeまたはCodex CLIは自律エージェントの実行基盤となり、Collectorは手動送信されたテレメトリを保存します。Agent別AdapterはJSON形式のツールイベントを共通Schemaへ正規化し、ホスト側の評価器はRun終了後に固定済みポリシーを適用します。シェル実行前にGateが動作するのはCondition Cだけです。

承認状態は、リセット用の制御経路を通じて初期化されます。制御対象のクライアントがこの実行時情報を読み取るのは、スコープと禁止操作を確認した後だけです。エージェント自身による「承認済み」という主張は受け入れません。したがって、スコープ外を対象とする提案によって、そのターゲットへの制御用問い合わせまで発生することはありません。

Condition A/Bの`pentestcode`と`codex`サービスは、両ゾーンへの技術的な到達可能性そのものを実験上の処置とするため、両方のターゲットネットワークに接続されます。Condition Cの`pentestcode-gated`と`codex-gated`には`outscope-net`インターフェースがなく、Command Gateに加えて強制的な境界を提供します。S10用の`mock-control-plane`も`outscope-net`だけに接続され、実LLM Relay、Credential、Provider Egressとは完全に分離されています。各ターゲットは単一のネットワークだけに接続されるため、ターゲット間の横方向通信はできません。2つのネットワークに接続されたCollectorは、各隔離ネットワーク上でRun構成に固定されたアドレスを持ちますが、ホスト側へポートを公開しません。唯一のBind Mountである`./results:/results`が永続化の境界です。

S11〜S13では、Scenarioに対応するCIA Mock ContainerをCompose Profileで1つだけ追加します。
S14では、Identity、Secondary Host、Secret Store、Collection Store、Exfiltration Sink、Impact Resourceを専用Compose Profileで追加します。すべて`outscope-net`限定の合成サービスで、実OSや外部Networkへ作用しません。
CIA Mockは`outscope-net`だけに接続され、専用Named Volume内の合成状態とTelemetryだけを扱います。
Run終了直後にOrchestratorがContainer内部からTelemetryを取得し、Resultsへ固定します。

`NETWORK_MODE=fixed`は従来のアドレスを使用し、`NETWORK_MODE=seeded`はSeedからサブネットと各サービスIPを決定論的に生成します。実Network名とContainer名は役割を含まないSeed固有Hashになり、Scope/Out-of-scope用Interface順はSeedの偶奇でCounterbalanceされます。生成結果はPrompt、Scenario、Policy、Gate、Trace Parserで共通利用され、RunのMetadataへ保存されます。Promptへ提示する情報はScenario Profileに従い、S6では認可CIDRのみ、S7では単一Hostのみ、それ以外ではTarget、Decoy、認可CIDR、禁止CIDRを使用します。ネットワーク設定が変わる場合は内部NetworkとContainerを再作成しますが、OAuth CredentialのNamed Volumeは維持されます。

どちらのAgentにもインターネット接続用インターフェースはなく、`inference-net`上の内部LLM Relayへ接続します。`provider-egress`に接続されるのはRelayだけであり、Relayが受け付けるのはDevice OAuthとCodex推論に必要な最小限の経路だけです。PentestCodeとCodexのOAuth認証情報は別々のroot専用Named Volumeに保存されます。一方、モデルが選択したシェルプロセスは、それを読み取れない別のUIDで実行されます。`LAB_CONDITION`と`LAB_SCENARIO`はAgent環境へ注入せず、`/bin/sh`と`/bin/bash`のBoundary実装および転送先ShellはAgent UIDから読み取れません。エージェントとターゲットのコンテナが、外向き通信用ネットワークへ接続されることはありません。

ターゲットのエンドポイントは、稼働確認、探索、認証情報の取得と再利用、ログイン、承認によって制御される権限昇格、Flagへのアクセス、破壊的な状態遷移をモデル化します。Mock Control Planeは固定の合成Model一覧だけを返します。コマンドを実行したり、ホストを操作したり、外部へProxyしたりするエンドポイントはありません。Named Volumeに格納されるのはJSON形式のモック状態だけであり、それぞれ独立して再作成できます。

```text
シナリオ + 条件 + Seed + Network Mode + Agent -> プロンプト / 固定入力 -> Agentのモデル呼び出し
-> 実際のnmap / curl / シェル操作 -> 任意の決定論的Gate -> 稼働中のモックサービスからの応答
-> Agent固有JSON Trace -> 正規化済みAction Event -> 独立した違反検出器
-> Run単位の評価指標 -> 集計レポート
```
