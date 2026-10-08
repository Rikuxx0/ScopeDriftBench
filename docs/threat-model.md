# 脅威モデル

## 保護対象資産

ホストのファイルシステム、Docker Control Plane、ローカルネットワーク、インターネット上のシステム、第三者は実験対象外です。破壊可能な唯一の資産は、合成ターゲットのJSON状態です。

## 制御

- ターゲットネットワークと推論ネットワークは内部ネットワークであり、固定されたPrivate Subnetを使用します。
- ホスト側へポートを公開したり、Host Networkを使用したりするサービスはありません。
- Privileged Containerはなく、Privilege Escalationは無効です。Capabilityは全体でDropされます。PentestCodeが保持するのは`SETUID`と`SETGID`だけであり、信頼されたOrchestratorがモデル選択の各Shell Childを`lab` UIDへ不可逆に降格するために使用します。
- Docker SocketやSource Tree全体を対象とするMountが、Attackerへ渡ることはありません。
- ターゲットはローカルソースからBuildしたMockであり、RCEや実在製品の脆弱性を含みません。
- Attacker Imageに含まれるのは、Pythonと制御対象のHTTP Clientだけです。
- PentestCode AgentとCodex Agentには外向き通信用のインターフェースがありません。Provider Networkへ到達できるのは、Allowlist方式のLLM Relayだけです。Host/Path Allowlistは、ChatGPT Device OAuthとCodex推論に限定されます。
- 各Agent Orchestratorは自身のOAuth認証情報を読み取れますが、モデルが選択したShell Commandは別UIDで動作し、`/auth`や`/state`を読み取れません。PentestCodeとCodexのCredential Volumeも分離されています。
- Condition Cでは、決定論的なShell Gateと`outscope-net`インターフェースの不在を併用します。
- ターゲットの状態は専用Named Volumeに保存され、ホストへのBind MountはResultsだけです。

## 残存リスク

Docker Engineの脆弱性、ホストの設定不備、Provider側のデータ処理、リソース枯渇、研究者による安全でないツールやAdapterの追加は、ソフトウェアレベルの保証対象外です。さらに強い隔離が必要な場合は、外部Egress Firewallとリソース上限を設定した使い捨てVM内でDockerを実行してください。LLM API Keyをエージェントコンテナへ追加してはいけません。固定済みのAgent BinaryとOAuth Relayは、信頼するコンピューティング基盤に含まれます。この分離が防御するのはモデルが選択したTool Commandであり、いずれかのComponentが悪意あるものへ置き換えられた場合ではありません。
