# Model ProviderとAgent Harness

Providerは推論先、Harnessはツール選択と実行を管理する実行基盤です。`codex_oauth`は従来のCodex CLI/PentestCodeで動きます。`ollama`と`lmstudio`はホスト側の独立`local` Harnessで動きます。Codex CLIがLM StudioのResponses APIに接続する[公式手段](https://lmstudio.ai/docs/integrations/codex)はありますが、このラボのOAuth Relayと隔離ネットワークを変更せずに導入する検証が済んでいないため、この組み合わせはCLIで拒否します。

| Harness | Provider | 状態 | ツール実行 |
|---|---|---|---|
| `codex` | `codex_oauth` | 既存経路 | Codex CLI、隔離Container |
| `pentestcode` | `codex_oauth` | 既存経路 | PentestCode、隔離Container |
| `local` | `ollama` | Mockで検証済み、実モデル未検証 | 型付き`Shell`、既存Codex Container |
| `local` | `lmstudio` | Mockで検証済み、実モデル未検証 | 型付き`Shell`、既存Codex Container |

Ollamaは[OpenAI互換Chat Completions](https://docs.ollama.com/api/openai-compatibility)とモデル一覧用の`/api/tags`、モデル能力用の`/api/show`を使用します。LM Studioは[OpenAI互換Chat Completions](https://lmstudio.ai/docs/developer/openai-compat)と[ネイティブのモデル一覧](https://lmstudio.ai/docs/developer/rest/list)を使用します。返されたTool Calling情報が欠ける場合は`unknown`と表示し、実際のTool Callが得られないRunをCapability Failureとして記録します。モデルにTool Calling非対応が明示されている場合と、LM Studioでモデル未ロードの場合は実行前に拒否します。

ローカル推論のHTTP接続はホスト側の信頼されたOrchestratorに限り、`base_url`に設定された1つのOriginと固定API経路だけを使います。Redirect、環境Proxy、モデル出力が指定したURLへの転送を拒否します。別マシンの場合は、そのサーバーを明示的に設定し、TLSまたはSSH Tunnelなどの保護された経路を用意してください。Agent Containerへホストの任意Directory、Docker Socket、Provider設定、直接Internet経路を追加していません。

Run Metadataには`harness`、`harness_version`、`provider`、`provider_version`、`model_id`、`model_revision`、`quantization`、`generation_parameters`、`tool_calling_mode`、`experiment_seed`を保存します。取得できない値は`null`のままとし、推測で補完しません。Raw Traceは`local_trace.jsonl`、共通Eventは`events.jsonl`です。Raw TraceにはTool要求、観測できたGate拒否、Tool結果を分けて記録します。Tool結果だけで対象への到達を推定しません。

## Ollamaの準備

Ollamaのローカルサーバーは既定で`localhost:11434`を使います。モデルはTool Callingに対応している必要があります。モデル一覧と能力はOllamaの[公式API仕様](https://docs.ollama.com/api/tags)、[Tool Calling説明](https://docs.ollama.com/capabilities/tool-calling)で確認してください。

`.pentestlab.yaml`の`providers.ollama.base_url`は、ホストMacなら`http://localhost:11434/v1`です。別マシンなら、ホスト側から接続できる明示的な推論サーバーのURLを設定します。別マシンのHTTPを公開ネットワークに晒さず、保護された経路を使用してください。

この環境で確認したコマンドは`./pentestlab models --provider ollama`です。サーバーが停止している場合は、接続失敗と原因確認の案内を表示しました。サーバー起動後は同じコマンドでモデルID、Context Window、Tool Calling、量子化、ロード状態を確認できます。取得できない項目は`unknown`です。

## LM Studioの準備

LM StudioのDeveloper画面でローカルサーバーを起動し、Tool Calling対応モデルをロードします。既定の接続先は`http://localhost:1234/v1`です。[モデル一覧API](https://lmstudio.ai/docs/developer/rest/list)にはロード状態とTool Use学習情報が含まれます。CLIは未ロードまたはTool Calling非対応と確認されたモデルを拒否します。

`.pentestlab.yaml`の`providers.lmstudio.base_url`をホスト側から接続できる推論サーバーに設定します。別マシン上で動かす場合は、保護された経路を用意してください。Agent Containerから直接接続する構成ではありません。

この環境で`./pentestlab models --provider lmstudio`を実行し、サーバー未起動時の接続エラーを確認しました。サーバー起動後は同じコマンドで利用可能なモデル情報を表示します。

## 共通の実験手順と検証範囲

Runの準備には`pentestlab run --harness local --provider <ollama|lmstudio> --model <モデルID> --prepare-only`を使い、表示されたRun IDを`pentestlab execute --run-id <Run ID>`へ渡します。ProviderのHTTP応答、異常応答、Model選択、Tool Call解析、CLI、共通Event生成はMockでテスト済みです。Composeの静的検証は通っています。実ラボは停止中で、両Providerのサーバーも起動していなかったため、実モデルとDockerを組み合わせた動的検証は未実施です。
