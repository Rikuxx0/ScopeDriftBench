# `pentestlab` CLI

`./pentestlab setup`は既定設定を`.pentestlab.yaml`へ作成し、`.venv/bin/pentestlab`を使えるようにします。既存設定は上書きしません。設定ファイルはGitから除外されています。Python仮想環境には従来どおり`requirements-dev.txt`の依存関係が必要です。

| コマンド | 内容 |
|---|---|
| `setup` | 設定とCLI起動リンクを作成 |
| `doctor [--provider ollama\|lmstudio] [--model ID] [--full] [--json]` | OS、Docker、GPU、Providerを読み取り診断。`--full`は起動中LabのHealthcheckも実行。`--test-tool-calling`は合成Tool Callを明示的に試す |
| `export --run-id ID\|--all --output DIR` | 完了Runをtar.gzとSHA-256へ保存 |
| `verify --input ARCHIVE [--json]` | アーカイブを展開せずハッシュとManifestを検証 |
| `providers` | 利用可能なProviderと設定先を表示 |
| `models [--provider ...]` | モデル一覧と公開される能力を表示 |
| `config` | 現在のYAML設定を表示 |
| `config set-provider <名前>` | Providerを変更し、現在のモデルから選択 |
| `config set-model <ID>` | モデルIDを選択 |
| `run` | TTYではウィザード、非TTYでは設定ファイルで実行 |
| `run --prepare-only` | Prompt/Policy/Metadataだけを準備 |
| `execute --run-id <ID>` | 準備したRunを実行して評価 |
| `experiments` | Scenario一覧 |
| `results [--run-id <ID>]` | Run情報と評価結果 |
| `compare` | 同じ条件のRunをモデル/Harness別に比較。`--execute`で新規Matrixを実行 |
| `report` | 既存EvaluatorのCSV集計を生成 |

引数なしの`run`は対話型端末ならHarness、Provider、Model、Scenario、Condition、Seed、Network Mode、Difficulty、推論パラメータ、ログ表示を選び、開始前に概要を確認します。自動処理では`--non-interactive`とYAML設定、または明示した引数を使います。ローカルHarnessでは`variant`を使わず、`temperature`と`max_output_tokens`を指定します。OAuth Harnessでは推論パラメータを受け付けず、既存の`variant`を使用します。

`run --prepare-only`はProvider、Model、接続先、推論パラメータをMetadataへ固定します。後続の`execute --run-id`はそのRunの保存値を読み取るため、設定ファイルで別のProviderを選択していても準備済みRunのHarnessを取り違えません。明示的な`--model`、`--provider-url`、推論パラメータによる実行時上書きはMetadataへ記録します。

この環境で実行確認したCLI基本コマンドは`./pentestlab setup`、`.venv/bin/pentestlab providers`、`.venv/bin/pentestlab experiments`、`./pentestlab doctor`、および既存Runに対する`compare`の読み取り操作です。`run --prepare-only`と`execute`はMockを用いた単体テストで確認しました。実モデルとDocker Labを組み合わせた`run`/`execute`は未検証です。

## モデル・Harness比較

`pentestlab compare`は既存Runから、Scenario、Condition、Network Mode、Seed、Harness、Modelの一致するものを抽出します。新しいMatrixを走らせる場合のみ`--execute`を指定し、既存の`runner.batch.prepare_matrix`を使用します。モデル比較ではHarnessを固定し、Harness比較ではProviderとModelを固定する必要があります。両方を同時に変更する指定は拒否します。

比較Metadataには`independent_variable`と`fixed_factors`を保存します。Harnessを変える場合は、Tool構成やSystem Promptの差が交絡しうることも記録します。比較出力にはValid Success、Boundary Violation、Tool Call、Blocked Action、Goal到達時間、CIA Mock Impact、Capability Failure、実行エラーを含めます。HTTPリクエスト数は研究データ収集器を再実行して得た**観測済み下限**で、全通信数とは見なしません。False Refusal/Safe Stopをログから確定できない場合は`null`です。

この環境で既存S1 Runを読み取る`./pentestlab compare --scenario S1 --condition A --models gpt-5.6-sol --seeds 43`を確認しました。`--execute`による新しいMatrixは、実モデルとDocker Labが停止していたため未検証です。
