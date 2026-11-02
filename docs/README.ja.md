# Discordテキスト履歴MCP

各メンバーがDiscord上で本人承認し、自分とBotの両方が閲覧できるテキスト履歴をChatGPT／Claudeなどから取得するための、独立したBotとMCPサーバーです。
録音機能、個人のDiscordトークン、Discord OAuthのクライアントシークレットは使いません。

## 管理者の初期設定

1. [Discord Developer Portal](https://discord.com/developers/applications)で専用アプリとBotを作成します。Message Content Intentを有効にし、アプリの状況に応じてDiscordの承認を取得します。
2. `bot` と `applications.commands` のスコープでサーバーへ導入します。権限はまず **View Channels / Read Message History**（権限値 `66560`）だけを付与します。Administratorを持つBotは起動・履歴取得時に拒否されます。
3. `config.example.json` を `config.json` にコピーし、公開HTTPSのorigin、サーバーID、許可する正確なOAuthコールバックURLを設定します。相対パスは設定ファイルのあるディレクトリを基準に解決します。
4. Botトークンを `secrets/bot-token` に保存します。`secrets` ディレクトリの権限は700、ファイルは600にします。
5. Python 3.12以上と[uv](https://docs.astral.sh/uv/)で起動します。

```sh
uv sync --locked
uv run discord-history-mcp --config config.json check
uv run discord-history-mcp --config config.json serve
```

6. `127.0.0.1:19230` をHTTPSリバースプロキシで公開します。[コンテナとTailscale Funnelの配置手順](deployment.md)を参照してください。Funnel経由の利用者はtailnet参加やTailscaleの導入が不要です。

公開する場合は専用ユーザー・コンテナなどで実行環境を分離してください。[セキュリティ上の前提と残るリスク](../SECURITY.md)も確認してください。

## メンバーの接続

1. ChatGPT／Claudeのブラウザ版に `https://公開ホスト/mcp` をMCP接続先として追加し、OAuth認証を開始します。登録方式を選べる場合は自動登録／DCRを選びます。
2. 認証ページに表示された `/mcp code:認証コード` を対象のDiscordサーバー内で実行します。
3. 自分にだけ表示されるBotの返信で接続元と戻り先を確認し、**Allow history access** を押します。
4. 開いたままの認証ページが接続元へ戻ると利用できます。別のメンバーは、自分のDiscordアカウントで同じ操作を行います。

`/mcp` は接続案内、`/mcp action:revoke` は本人の、そのサーバーへの全接続の解除です。
認証コードは10分、アクセストークンは1時間、接続の許可は30日で失効します。すでにAI側へ渡った会話の回収はできません。

## 取得できるもの

- `whoami`: 接続した本人とサーバーの確認
- `list_channels`: 閲覧可能なテキスト・告知・フォーラム等
- `list_threads`: 指定チャンネルのアクティブスレッド
- `get_messages`: 履歴を1～100件ずつ取得。古い順で、前後のページを取得可能
- `search_messages`: 指定チャンネル内の最大500件を文字列検索。全履歴検索ではなく走査範囲を返す

DM、ボイス・ステージチャンネル内のテキストは対象外です。アーカイブ済みスレッドはID指定で取得できますが、一覧取得はアクティブなものだけです。非公開スレッドは本人とBotに所属またはManage Threads権限が必要です。

## 開発・検証

```sh
uv sync --locked --group dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest -q
uv build
```

テストは架空のDiscordデータとローカルHTTPで実行します。実際のDiscordアプリやChatGPT／Claudeアカウントでの接続確認は、各配置先で別途行ってください。既存の別Botをそのまま流用すると、そのアプリのギルドコマンドとの競合が起こるため、新しい専用アプリを使ってください。
