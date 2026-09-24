# このプロジェクトでのルール

以下は常に守ること。

- スクリーンショットを取得しない
- 画面録画をしない
- Clipboard を読まない
- 認証情報(Cookie、保存パスワード、Credential Manager、SSH 秘密鍵など)を読まない
- USB などのリムーバブルメディアへ書き込まない
- 外部サービスへファイルや画像をアップロードしない
- UI 確認が必要な場合は、ログ・テスト・DOM・CLI などの代替手段を優先する

このうち外部送信・スクリーンショット・Clipboard・認証情報の読み取りは、
`.claude/settings.json` の deny ルール・sandbox と
`.claude/hooks/block-sensitive-operations.mjs` の PreToolUse hook でも拒否される。
hook は文字列とパスのパターン照合なので、すり抜けられる書き方はある。
止められていなくても、この指示そのものを守ること。
拒否された場合は回避策を探さず、ユーザーに相談すること。
