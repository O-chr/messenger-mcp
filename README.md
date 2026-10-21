# Messenger MCP

個人Facebook Messengerの許可済みチャットをChatGPT／Codexから扱う、本人専用のMCPサーバー。

- `messenger_status`: 接続と有効な権限
- `messenger_list_chats`: 許可されたチャットだけの一覧
- `messenger_read_history`: セキュアストレージから許可チャットのE2EEテキストを新しい順にページ取得
- `messenger_send_message`: 宛先と本文を本人が確認してからE2EE送信
- `messenger_send_status`: 本人確認待ち・送信結果の確認（送信処理は行わない）

## 構造

ChatGPT／Codex → HTTPS + 本人Google認証 → Node MCPサーバー → ローカルJSON-lines → Go Messenger CLI → Messenger E2EE。
Go側は `mautrix/meta` を基にした `internal/messengercli`。デバイス鍵を保持するプロセスは1つで、複数のMCPクライアントが共有する。Web公開するのは認証済みMCPのみ。Cookieやデバイス鍵をツールに渡さない。

このリポジトリにNode MCPサーバーとGo CLIをまとめている。

- `src/`: MCPツール、権限管理、Google OAuth、本人確認ページ
- `backend/`: Go CLIと、その基盤となるmautrix/metaのソース
- `plugin/`: ChatGPT／Codex向けプラグイン・スキル
- `docs/`: 接続・検証記録と移行元の情報

Goコードのライセンスと例外は [backend/LICENSE](backend/LICENSE) と [backend/LICENSE.exceptions](backend/LICENSE.exceptions) を参照。取り込み元のコミットは [docs/provenance.md](docs/provenance.md) に記録している。

## 権限設定（Mac所有者のみ）

```sh
npm run admin -- chats
npm run admin -- permissions read,write
npm run admin -- allow 123456 read
npm run admin -- allow 123456 read,write
npm run admin -- allow 123456 read,write --group
npm run admin -- deny 123456
npm run admin -- allow-all read,write --groups
```

設定は `~/.config/messenger-personal-mcp/config.json` (0600)。上位フォルダーは0700。グローバル権限と各チャットの権限の両方が必要。`MESSENGER_MCP_PERMISSIONS` が追加の上限になる。初期設定は全チャット拒否。`allow-all` はその時点でCLIが把握しているチャットだけを明示的に許可する。新規チャットは自動で許可しない。設定変更は操作直前にも再チェックする。ツール一覧を更新するにはクライアントを再接続する。

Codex等のMCPフォーム対応クライアントでは、その場で送信を確認する。フォーム未対応のChatGPTでは、送信せず本人確認リンクを返す。本人がGoogle認証後、宛先・本文を確認してページ内の送信ボタンを押すと1回だけ送信する。リンクのGETやプレビューだけでは送信しない。AIは本人に代わって承認しない。本人専用HttpOnly Cookie・CSRF検証・Origin検証を使い、他のMCPクライアントは送信結果を取得できない。承認期限10分、同一リクエストを重複作成しない。拒否・キャンセル・確認中の権限変更では送信しない。権限を広げる管理ツールはMCPに公開しない。送信結果が不明な場合は自動再送しない。

## 読み取りと制限

常駐の受信機は持たない。Messengerへは、ツールがMetaとの通信を必要としたときにだけ接続し、最後の利用から2分たつと切断する。受信したメッセージをローカルに保存しない。起動時に旧版の受信キャッシュ（`messages.db`）が残っていれば削除する。

読み取りはすべて `messenger_read_history` で、セキュアストレージから行う。事前に `/history/setup` で本人がGoogle認証し、6桁のMessenger復元用PINを入力しておく。PINは最初の1回だけで、保存せずMCPにも公開しない。復元した履歴デバイス鍵は既存の私有プロファイルに保存し、登録結果が不明なら自動再試行しない。

`messenger_read_history` は許可されたE2EEチャットだけを最大50件ずつ新しい順に取得し、本文はメモリー上で返してディスクへ保存しない。`has_more` と `before_ms` で古いページへ進む。サーバー上のバックアップに残る範囲のみで、削除済み・未バックアップ・未対応形式の全復元は保証しない。送信直後のメッセージがバックアップに反映されるまでの時間は未検証。

現在のCLIはE2EE宛先が解決できるチャットだけ送信可能。消えるメッセージ・メディアには非対応。旧形式のグループ等は権限があっても送信できない。非暗号化経路へのフォールバックはしない。Macが起動し、ネット接続している必要がある。Metaの非公式プロトコルに依存する。

## 起動

```sh
npm ci --ignore-scripts
npm test
npm run build:all
```

Node.js 22以上と、`backend/go.mod` の指定を満たすGoツールチェーンが必要。`build:all` は `backend/bin/messenger` と `dist/` を生成する。MCPは標準で同じリポジトリ内のCLIを使い、`MESSENGER_BIN` で変更できる。

初回のCookie取り込みとチャット同期はMCPを起動する前に行う。コピーしたcURLはコマンドとして実行せず、CLIの非表示入力へ貼り付ける。

```sh
./backend/bin/messenger login
./backend/bin/messenger chats
npm run admin -- permissions read,write
npm run admin -- allow 123456 read,write
```

```sh
GOOGLE_OAUTH_JSON=/private/path/google-oauth.json \
MESSENGER_MCP_ALLOWED_EMAIL=owner@example.com \
MESSENGER_MCP_PUBLIC_URL=https://your-domain.example \
MESSENGER_MCP_PERMISSIONS=read,write npm run http
```

Google Web OAuthクライアントの承認済みリダイレクトに `<PUBLIC_URL>/oauth/google/callback` を追加する。GoogleのIDトークン署名・audience・issuer・nonce・メール確認済みフラグ・所有者メールを検証する。

MCP OAuthはDCR + PKCE、リソース固定、短期アクセストークン、更新トークンのローテーション。保存するトークンはSHA-256ハッシュ。LINE等とトークン保存を分ける。各HTTPセッションは認証したクライアントに固定。

- 公開先: `https://messenger-mcp.the-true-works.com/mcp`
- ローカル: `127.0.0.1:8791`
- launchd: `com.personal.messenger-personal-mcp` / `com.personal.messenger-personal-mcp.tunnel`
- 認証・権限・ログ: `~/.config/messenger-personal-mcp/`
- Messenger Cookie・鍵: `~/Library/Application Support/messenger-cli/`

ローカルプロファイルは所有者権限のみだが、Cookie・デバイス鍵そのものは平文。GitやDriveに保存しない。ログへ認証情報・本文を出さない。

`npm start` はstdio用。HTTP常駐と同時に同じMessengerプロファイルを開かない。`MESSENGER_BIN`、`MESSENGER_STATE_DIR`、`MESSENGER_MCP_CONFIG` でローカル配置を変更できる。

## 検証

`npm test`: 実際のMCP SDKクライアントで権限・確認・取り消しを検証。本人確認ページのGoogleログイン、Cookie/CSRF/Origin、二重承認、権限取り消し、結果不明時の再送防止も偽バックエンドで検証。OAuth PKCE・所有者限定・リソース固定・トークン更新・セッション隔離はHTTPで検証。実メッセージは送らない。
Go側もローカルプロファイルと偽イベントで、ネット通信前の拒否・許可済みチャットだけの保存・取り消し時削除・保存上限を検証する。
