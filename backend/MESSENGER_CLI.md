# Messenger CLI（ローカル試作）

`mautrix-meta` の Web 接続実装 `messagix` と、Messenger E2EE に対応した
`whatsmeow` を使う独立 CLI。Matrix サーバーは不要。

レビュー・開発開始時の upstream は
`c4099692425e85b167adb76954c78baea201af89`。
既存のブリッジ起動処理は変更せず、`cmd/messenger` を追加している。

## ビルドと確認

Go 1.27.3、CGO、C コンパイラがある環境で実行する。macOS では Command Line
Tools の clang を使用する。CLI 自体には libolm や ffmpeg は不要。

```sh
./build-messenger.sh
./bin/messenger --help
go test -race ./internal/messengercli ./cmd/messenger
go vet ./internal/messengercli ./cmd/messenger
```

Go を PATH に追加していない場合は `GO=/absolute/path/to/go ./build-messenger.sh`。
取得済みのビルド済みバイナリではなく、確認したソースからビルドする。

## 接続

ブラウザの Facebook / Messenger に本人がログイン済みであることが前提。
DevTools → Network → `graphql` で絞り込み、同じサービスのリクエストを
Copy → Copy as cURL でコピーする。

macOS のクリップボードから、そのままローカル CLI に渡せる。
コピー内容をチャット、チケット、シェルのコマンド引数には貼らない。

```sh
pbpaste | ./bin/messenger login --stdin --platform facebook
```

`messenger.com` からコピーした場合は `--platform messenger`。
コピーした curl は文字列として解析するだけで、シェル実行はしない。
`c_user` / `xs` / `datr` と任意の `sb` だけを取り込み、他のヘッダーや本文は捨てる。
Cookie JSON または Cookie ヘッダーも入力可能。
`./bin/messenger login` は入力を非表示にするが、複数行 curl には `--stdin` を使う。
`--cookie-file` も利用可能だが、入力ファイルは通常ファイル・権限 600 に限る。

アカウントを Web 通信で確認した後、CLI 専用の暗号鍵を生成して E2EE 端末を登録する。
既存の端末鍵があれば再利用する。別アカウントの Cookie で上書きしようとした場合は拒否。
`login` は端末登録を許可するコマンドで、`chats` / `send` は端末を勝手に再作成しない。
Meta 側に追加認証やアカウント確認を求められたら公式サイトで本人が対応する。

## チャット一覧とテキスト送信

```sh
./bin/messenger status
./bin/messenger chats
./bin/messenger chats --pages 1 --json
./bin/messenger chats --cached
./bin/messenger send --chat CHAT_ID --text '送信テストです' --dry-run
./bin/messenger send --chat CHAT_ID --text '送信テストです'
```

`status` は保存状態のみ表示し、有効なセッションかの確認はしない。
`chats` は初期同期、`--pages N` は同期グループごとに最大 N ページの追加取得。
初期版で全チャット取得を保証しない。取得済みメタデータには本文を保存しない。

送信先は `chats` の数値 ID を完全一致で指定する。名前の曖昧検索では送信しない。
ハイブリッドチャットの Facebook ID → E2EE JID の対応も保存・適用する。
非 E2EE / 不明な宛先 / 消えるメッセージ設定のチャットは拒否し、平文送信へ切り替えない。
送信前に宛先・本文を表示し、`SEND` 入力で確認する。
ローカルで確認済みの操作を自動化する場合だけ明示的な `--yes` を使用する。

本文のシェル履歴への保存を避けるにはファイルまたは stdin を使う。

```sh
./bin/messenger send --chat CHAT_ID --text-file /absolute/path/to/message.txt
printf '%s' '送信テストです' | ./bin/messenger send --chat CHAT_ID --stdin --yes
```

成功出力の `server_acknowledged` はサーバーによる受理を表す。配達済み・既読の保証ではない。
送信失敗時はメッセージ ID と「結果不明」を表示する。アプリ側で確認してから再実行する。
CLI は別 ID のメッセージを自動再送しない（依存ライブラリの同一 ID のプロトコル再試行はあり得る）。

## 保存と権限

macOS の標準保存先は `~/Library/Application Support/messenger-cli/`。
プロファイルを分ける場合はグローバルオプションをコマンドの前に置く。

```sh
./bin/messenger --state-dir /absolute/private/profile status
```

- ディレクトリ 700、ファイル 600。symlink の保存先や権限が広すぎる既存ファイルは拒否。
- `account.json` にログイン Cookie、本人 ID、最小限のチャットメタデータ。
- `device.db` に端末秘密鍵、更新される暗号セッション。
- `.lock` の OS ロックで同じプロファイルの同時起動を防ぐ。
- upstream の個別ロガーとグローバルロガーの両方を無効化する。
  ネットワークエラーにもトークンや応答本文を出さない。

**この初期版はファイルの権限制御で保護し、保存ファイル自体をアプリ独自には暗号化しない。**
暗号化されたローカルディスクで使用し、Google Drive などの同期フォルダには置かない。
同じ OS ユーザーで動くマルウェアや管理者から守るものではない。
Cookie / 鍵 / SQLite ジャーナルを、ログや Git 管理に追加しない。

## 初期版の範囲

テキスト E2EE 送信まで。履歴バックアップの PIN 復元、メディア、MCP、常時監視は未実装。
実アカウントでのログイン・送信確認は、オフラインテストと区別して記録する。

## 検証記録

- Go 1.27.3 / macOS arm64 でビルド。
- オフラインで Cookie 解析、秘密情報のエラー非表示、プロファイル権限と排他、
  アカウント混同防止、E2EE 宛先マッピング、送信拒否と dry-run をテスト。
- 2026-10-20、本人の Facebook Cookie をローカル入力し、本人確認と E2EE 端末登録・接続に成功。
- 実機で初期同期と追加ページ取得、DM の表示名補完を確認（確認時点で23チャット）。
- 同日21:36:06 JST、ユーザー指定の個人チャットへのテキスト1通を送信。
  サーバー受理応答と、公式ブラウザ画面の「送信済み」表示を確認。
- 送信コマンドは既存の端末鍵を再利用し、端末を再登録していない。
- 初回の実機ログインでは upstream のグローバル警告ログが出たため、全ロガーを抑止する修正を追加。
  修正後のチャット同期・送信で生ログが出ないことを確認し、回帰テストも追加した。
- Cookie・鍵・実データ・テスト送信先の内部IDは、この文書やソース管理に含めない。

## MCP receiver backend

The `bridge --policy PATH --permissions read,write` subcommand is an internal,
long-running JSON-lines backend for `messenger-personal-mcp`. It holds the profile
lock and shares a single E2EE device connection across MCP clients. The backend
independently checks the owner's private policy for every read and send, including
exact chat/JID binding, global read/write permissions and explicit group opt-in.
The MCP wrapper handles per-send user confirmation; do not expose this internal
process or the unrestricted CLI to a remote client.

Only explicitly readable chats have received text cached in the local private
`messages.db`: at most seven days and 500 per chat. Revocation purges cached text.
Disappearing messages are excluded; older secure-storage backup history and media
are not restored. Outgoing text is cached after the server acknowledgement only
when read permission also allows it. Neither credentials nor message bodies are
written to diagnostics. Use the MCP wrapper's owner-only admin command to edit
permissions; the backend has no permission-grant operation.
