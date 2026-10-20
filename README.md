# 個人Messenger MCP

個人Facebook Messengerの許可済みチャットをChatGPT／Codexから扱う、本人専用のMCPサーバー。

- `messenger_status`: 接続と有効な権限
- `messenger_list_chats`: 許可されたチャットだけの一覧
- `messenger_read_messages`: 許可されたチャットの最近のテキスト
- `messenger_send_message`: 宛先と本文を本人が確認してからE2EE送信

## 構造

ChatGPT／Codex → HTTPS + 本人Google認証 → Node MCPサーバー → ローカルJSON-lines → Go Messenger CLI → Messenger E2EE。
Go側は `mautrix/meta` を基にした `internal/messengercli`。デバイス鍵を保持するプロセスは1つで、複数のMCPクライアントが共有する。Web公開するのは認証済みMCPのみ。Cookieやデバイス鍵をツールに渡さない。

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

送信にはMCPフォーム確認に対応したクライアントが必要。未対応・拒否・キャンセル・確認中の権限変更では送信しない。権限を広げる管理ツールはMCPに公開しない。送信結果が不明な場合は自動再送しない。

## 読み取りと制限

受信機を起動してから受け取ったE2EEテキストを、許可されたチャットだけローカルに保存する。過去のセキュアストレージ履歴は復元しない。最大7日・各500件、1回の読み取り最大50件。権限を取り消すと保存済み本文を削除する。消えるメッセージ・メディアには非対応。

現在のCLIはE2EE宛先が解決できるチャットだけ送信可能。旧形式のグループ等は権限があっても送信できない。非暗号化経路へのフォールバックはしない。Macが起動し、ネット接続している必要がある。Metaの非公式プロトコルに依存する。

## 起動

```sh
npm ci --ignore-scripts
npm test
npm run build
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
- Messenger Cookie・鍵・本文キャッシュ: `~/Library/Application Support/messenger-cli/`

ローカルプロファイルは所有者権限のみだが、Cookie・デバイス鍵・本文DBそのものは平文。GitやDriveに保存しない。ログへ認証情報・本文を出さない。

`npm start` はstdio用。HTTP常駐と同時に同じMessengerプロファイルを開かない。`MESSENGER_BIN`、`MESSENGER_STATE_DIR`、`MESSENGER_MCP_CONFIG` でローカル配置を変更できる。

## 検証

`npm test`: 実際のMCP SDKクライアントで権限・確認・取り消しを検証。OAuth PKCE・所有者限定・リソース固定・トークン更新・セッション隔離はHTTPで検証。実メッセージは送らない。
Go側もローカルプロファイルと偽イベントで、ネット通信前の拒否・許可済みチャットだけの保存・取り消し時削除・保存上限を検証する。
