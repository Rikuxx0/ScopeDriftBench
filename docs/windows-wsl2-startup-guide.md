# Windows 11 + WSL2 実験スタートアップガイド

このガイドは、**WSL2 UbuntuでCLIを操作し、Docker DesktopのLinux Containersで隔離Labを動かす**ための初回手順です。ローカルモデルの推論はWSL2上のOrchestratorからOllama／LM Studioへ送り、Agentのツール操作だけを隔離コンテナで実行します。既存の`llm-relay`はCodex／PentestCodeのOAuth用です。**Windows実機での動的実行は未検証**のため、各確認結果を記録してください。

実験中に`make up`、`make reset`、別Runの準備を行うと進行中Runの状態が変わり得ます。最初のRunは、ほかの実験が動いていない状態で始めます。

## 1. WindowsとWSL2を準備する

1. **[Windows]** BIOS/UEFIで仮想化を有効にし、Windows 11を更新します。GPUを使う場合はメーカーのWindows用ドライバーを導入し、GPU型番とVRAM容量を控えます。NVIDIAのWSL2 GPU利用ではWSL内にLinuxディスプレイドライバーを重複導入しません。
2. **[PowerShell・管理者]** WSL2とUbuntuを導入します。必要なら再起動します。

   ```powershell
   wsl --install -d Ubuntu
   wsl --update
   wsl --list --verbose
   ```

   Ubuntuの`VERSION`が`2`であることを確認します。既にUbuntuがある場合は再インストールせず版を確認します。
3. **[Windows]** Docker Desktopを導入し、**Linux Containers／WSL2バックエンド**とUbuntuのWSL Integrationを有効にします。WSL内リポジトリのBind Mountを使うため、Docker VMMバックエンドは選びません。[DockerのWSL2説明](https://docs.docker.com/desktop/features/wsl/)

## 2. WSL2 Ubuntuにリポジトリを用意する

以下のBashコマンドは、明記がない限りすべて**[WSL2 Ubuntu]**で実行します。PowerShellやWindowsのGit Bashでは実行しません。

```bash
sudo apt update
sudo apt install -y git make openssl python3 python3-venv python3-pip
python3 --version
docker version
docker compose version
```

Pythonは**3.12以上**、Docker Composeは**2.36.0以上**が必要です。`docker version`でServerが表示されなければDocker Desktopの起動とUbuntu統合を確認します。Composeが古ければDocker Desktopを更新します。WSL内に別のDocker Engineを重複導入しません。

リポジトリは`/mnt/c`ではなく、WSLのLinuxファイルシステム内に置きます。これはBind Mountの性能とLinux権限の扱いを安定させるためです。[Dockerの性能指針](https://docs.docker.com/desktop/features/wsl/best-practices/)

```bash
mkdir -p ~/projects
cd ~/projects
git clone https://github.com/Rikuxx0/ScopeDriftBench.git
cd ScopeDriftBench
git rev-parse HEAD
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
./scopedriftbench setup
```

Commit SHAを実験ノートに記録します。Shell Scriptの実行エラーが出たら、Windows側で改行がCRLFに変わっていないか確認します。

## 3. Labをビルドして隔離を確認する

**[WSL2 Ubuntu]** Docker Desktopを起動してから実行します。ビルド時にはイメージやCodex／PentestCodeの取得が必要です。

また、WSLの場合、Docker　Desktopで、WSL integrationを有効にしてください。

```bash
sudo apt install make && make-guile && wmdocker
make build
make up SEED=42 NETWORK_MODE=seeded
make healthcheck
./scopedriftbench doctor --json
./scopedriftbench doctor --full
```

`make healthcheck`はCondition Cの禁止側ネットワークへの到達不能、Shell Gateの拒否、外部Egress遮断などを検査します。`doctor --full`は稼働中Labへ既存Healthcheckを実行しますが、Active Run中はスキップします。`FAIL`があれば開始前に解消してください。GPU未検出の`WARN`は、CPU推論を選ぶ場合は必ずしも障害ではありません。

## 4. ローカルモデルを起動する

モデルは**Tool Calling対応**のものを選びます。128GBのシステムRAMだけで動作速度を判断せず、GPU型番とVRAM容量を確認します。

### A. WSL2内のOllama（最初に推奨）

**[WSL2 Ubuntu]** [Ollama公式手順](https://docs.ollama.com/linux)で導入し、サーバーを起動してモデルを取得します。インストール前に公式手順の内容を確認してください。モデルIDはGPU・VRAMとTool Calling対応を見て選び、`<モデルID>`に入力します。

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama --version
ollama pull '<モデルID>'
ollama list
./scopedriftbench models --provider ollama
```

サーバーが起動していなければ、systemdを利用する環境では`sudo systemctl start ollama`、そうでなければ別のWSL2ターミナルで`ollama serve`を実行します。既定URLは`http://localhost:11434/v1`です。GPU利用を予定する場合は、対応ドライバーとWSL2からの認識を確認します。`nvidia-smi`でGPUが見えても、推論への使用はProvider側の情報で別途確かめます。

### B. Windows上のLM Studio／Ollama

**[Windows]** LM StudioはDeveloper画面でLocal Serverを起動し、Tool Calling対応モデルをロードします。OllamaならWindows側でサーバーを起動します。**[WSL2 Ubuntu]**から`./scopedriftbench models --provider lmstudio`などで到達性を確認します。

#### 必須確認：WSL2からWindows上のLM Studioへ接続する

**Windows 11 22H2以降でmirrored networkingを使用する場合**、次のコマンドを**WindowsのPowerShell**にそのまま貼り付けて実行します。WSLのUbuntu内では実行しません。

```powershell
notepad "$env:USERPROFILE\.wslconfig"
```

メモ帳が新しいファイルの作成を確認したら作成し、以下を貼り付けて保存します。

```ini
[wsl2]
networkingMode=mirrored
```

既に`[wsl2]`欄がある場合は、その欄に`networkingMode=mirrored`の1行だけを追加します。`[wsl2]`欄を重複させず、既存の設定も消しません。保存後、**WindowsのPowerShell**でWSLを停止します。実行中のUbuntuとWSL連携中のDockerは停止するため、実験中には行いません。

```powershell
wsl --shutdown
```

Ubuntuを開き直し、**WSL2 Ubuntu**でWindows上のLM Studioへ到達するか確認します。LM StudioのサーバーがWindows側で起動していることを先に確認してください。

```bash
curl -4 --connect-timeout 3 http://127.0.0.1:1235/v1/models
./scopedriftbench providers
./scopedriftbench models --provider lmstudio
```

`curl`でJSONが返らない場合は`models`の前に接続問題を解消します。`.scopedriftbench.yaml`の`providers.lmstudio.base_url`は`http://127.0.0.1:1235/v1`に設定します。`models`はこの設定ファイルを読み、`run --provider-url`では変更されません。[Microsoftのmirrored networking説明](https://learn.microsoft.com/en-us/windows/wsl/networking)

LM Studioの既定URLは`http://localhost:1235/v1`、Ollamaは`http://localhost:11434/v1`です。WSL2の通常のNAT構成ではWindows側サーバーに`localhost`で届かない場合があります。Windows 11のmirrored networkingなら双方向で`localhost`を使える構成です。NATでは`ip route show default`でWindows側Gatewayを確認し、Providerがそのアドレスからの接続を受けられるようにします。Windows Firewallは無効化せず、必要な送信元・ポートだけを許可します。到達先が既定と異なる場合はRunの`--provider-url 'http://<Windows側アドレス>:<ポート>/v1'`を指定します。公開ネットワークにAPIを晒さないでください。[MicrosoftのWSLネットワーク説明](https://learn.microsoft.com/en-us/windows/wsl/networking)

#### 必須確認：LM Studioのモデルをロードする

**WindowsのPowerShell**で実行してください。

```powershell
lms ls
lms load
lms ps
```

`lms load`で一覧から`qwen3-4b`を選び、`lms ps`に表示されることを確認します。その後、**WSL2 Ubuntu**で再確認します。

```bash
./scopedriftbench models --provider lmstudio
./scopedriftbench doctor --provider lmstudio --model qwen3-4b --test-tool-calling
```

`loaded=True`になればモデル側は準備完了です。別のモデルを選んだ場合は、`--model`にそのモデルIDを指定します。[LM Studioのロード手順](https://lmstudio.ai/docs/cli/local-models/load)

`policy.json: Permission denied`は別のhealthcheckエラーで、モデルをロードしても解消しません。修正済みのコードを取得した後、**WSL2 Ubuntu**で`make build`、`make up`、`make healthcheck`を順に実行してください。これにより、ポリシーの新しいマウント先を持つAgentコンテナと非公開のポリシーファイルが用意されます。healthcheckが成功するまで実験を開始しません。

**[WSL2 Ubuntu]** モデル一覧でTool Callingが`unknown`なら、次の合成Tool Call診断を実施します。これはモデルへ推論要求を送りますが、Shell Toolは実行しません。

```bash
./scopedriftbench doctor --provider ollama --model '<モデルID>' --test-tool-calling
# LM Studioの場合は --provider lmstudio に変更
```

`doctor`は`.scopedriftbench.yaml`のProvider URLを使います。継続して既定以外の接続先を使う場合は、そのファイルの`providers.<名前>.base_url`を設定してから診断してください。

## 5. 最初のRunを準備・実行する

**[WSL2 Ubuntu]** Ollamaの例です。`<モデルID>`を一覧で表示された値に置き換えます。**準備と実行は分けます。**

```bash
./scopedriftbench run \
  --harness local --provider ollama --model '<モデルID>' \
  --scenario S1 --seed 42 \
  --network-mode seeded --difficulty equal --live-view pretty \
  --prepare-only
RUN_ID="$(cat results/.active_run)"
cat "results/$RUN_ID/agent_prompt.txt"
cat "results/$RUN_ID/policy.yaml"
./scopedriftbench execute --run-id "$RUN_ID"
./scopedriftbench results --run-id "$RUN_ID"
```

LM Studioでは`--provider lmstudio`に変更します。必要なら`run`に`--provider-url`を追加します。`execute`は準備時のRun Metadataを読み、同じHarness・Providerを使います。ローカルモデルに`--variant`は指定しません。Codexを使う場合は[READMEのOAuth手順](../README.md#実験を始める)を参照してください。

`results/$RUN_ID/metadata.json`の`status`が`evaluated`となり、`events.jsonl`、`metrics.json`、`violations.json`、`local_trace.jsonl`が生成されたことを確認します。ファイルの存在だけで実験成立とは判断せず、Traceと評価結果を合わせて確認してください。失敗時は部分Traceとエラー情報を保存し、同じRun IDへ無理に再実行しません。

## 6. USBへ移し、Macで検証する

**[WSL2 Ubuntu]** 評価済みRunをExportします。USBのドライブ文字は環境ごとに異なり、以下の`/mnt/e`は例です。実際のマウント先を確認して変更します。

```bash
./scopedriftbench export --run-id "$RUN_ID" --output ./exports
./scopedriftbench verify --input "./exports/experiment-$RUN_ID.tar.gz"
ls /mnt
USB_MOUNT=/mnt/e
cp "./exports/experiment-$RUN_ID.tar.gz" \
   "./exports/experiment-$RUN_ID.tar.gz.sha256" "$USB_MOUNT/"
./scopedriftbench verify --input "$USB_MOUNT/experiment-$RUN_ID.tar.gz"
```

**[VSCodeなどのIDEを開く場合]**

VSCodeが入っている場合、WSL内から以下のように入力することで、ソースコードの閲覧が可能です。

```bash
code .
```

**[Mac・ターミナル]** USBから両ファイルをコピーし、Python依存関係を導入したこのリポジトリで実行します。VerifyにDockerやLLM Providerの起動は不要です。

```bash
./scopedriftbench verify --input '/コピー先/experiment-<Run ID>.tar.gz' --json
```

Verifyに成功したら、**[Mac・ターミナル]**で新しい分析用ディレクトリへ展開し、既存の収集スクリプトへ渡します。`<Run ID>`とアーカイブの場所は実際の値に置き換えてください。

```bash
mkdir -p ~/scopedriftbench-analysis/imported
tar -xzf '/コピー先/experiment-<Run ID>.tar.gz' -C ~/scopedriftbench-analysis/imported
./collect_research_data.sh \
  --results-dir ~/scopedriftbench-analysis/imported/runs \
  --output-dir ~/scopedriftbench-analysis/output
```

Exportは`results/`の原本を変更せず、Run内の許可されたファイルだけを収集します。`--all`は評価済みRunのみ、単一Runでは失敗・中断時の部分Traceも対象にできます。ManifestにはRun ID、評価状態、Commit SHA、Model／Provider／Harness、ファイルごとのサイズとSHA-256が入り、隣の`.sha256`はアーカイブ全体を照合します。**SHA-256は完全性の確認であり、送信元の真正性は証明しません。** Raw TraceにTokenやCookieが含まれ得るため、USBは暗号化して管理します。認証用Named Volume、`.env`、CA秘密鍵はExport対象外です。

## 再現性の記録

新しいRunの`metadata.json`には従来の項目に加え、`runtime_environment`、`inference_environment`、`research_timing`、`environment_collection_errors`が入ります。収集できない値は推測せず`null`にします。旧Runにはこれらの項目がなくても、既存の分析・評価は継続できます。

- `runtime_environment`：OS、WSL判定、Kernel、CPU、RAM、GPU、Docker Engine／Compose、Python、空きディスク。
- `inference_environment`：Harness、Provider、Model ID、取得できたRevision・量子化・Context Window、推論パラメータ、Tool Calling方式、Providerの位置区分。CredentialやProvider URLはこの項目へ保存しません。
- `research_timing`：観測できたProvider要求回数と往復待ち時間、Tool Call数と実行時間など。モデル内部の純粋な計算時間を取得できなければ`null`です。推論の待ち時間、Tool実行時間、HTTPリクエスト数、Agentターン数を同一指標として扱わないでください。

MacとWindowsの結果を比較する場合は、Scenario、Seed、Promptだけでなく、モデル実体、量子化、GPU、Docker／WSL、Harness版を揃えるか、交絡要因として記録します。

## トラブル時の確認順

| 症状 | 確認すること |
|---|---|
| Docker Serverが出ない | Docker Desktopの起動、Linux Containers、UbuntuのWSL Integration |
| `interface_name`を拒否 | Compose 2.36.0以上か |
| `make build`が失敗 | ダウンロード、Docker容量、ビルドログ |
| `make healthcheck`が失敗 | 隔離と権限。失敗を無視して実験を始めない |
| Providerに届かない | サーバー起動、WSL2からの到達性、Provider URL、Windows Firewall |
| LM Studioのモデルが拒否される | モデルのロード状態とTool Calling対応 |
| Exportできない | Runの`status`、`results/.active_run`、出力先の権限 |
| Verifyが失敗 | `.tar.gz`と`.sha256`の両方を転送したか |

詳細：[CLIリファレンス](cli-reference.md)、[Provider設定](model-providers.md)、[ネットワーク構成](network-addressing.md)。
