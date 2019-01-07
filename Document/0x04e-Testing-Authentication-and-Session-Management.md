## Mobile App Authentication Architectures

認証と認可の問題は、一般的なセキュリティ上の脆弱性です。 実際、彼らは一貫して[OWASP TOP10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project "OWASP Top Ten Project")で2位にランクされています。

ほとんどのモバイルアプリは、何らかのユーザー認証を実装しています。認証およびステート管理ロジックの一部がバックエンドサービスによって実行されていても、認証はその共通実装を理解することが重要な、ほとんどのモバイルアプリケーションアーキテクチャの不可欠な部分になります。

基本的な概念はiOSとAndroidで共通しているので、この一般的なガイドでは、一般的な認証と認証のアーキテクチャと落とし穴について説明します。ローカルな生体認証などOS固有の認証の問題については、それぞれのOSに関する章で説明します。

### Stateful vs. Stateless Authentication

通常、モバイルアプリはトランスポート層としてHTTPを使用しています。HTTPプロトコル自体はステートレスなので、ユーザーの後続のHTTP requestをそのユーザーに紐付ける方法が必要です。そうしないと、requestごとにユーザーの資格情報を送信する必要があります。また、サーバとクライアントの両方は、ユーザデータ(ユーザの権限や役割など)を検証する必要があります。これは、2つの異なる方法で行うことができます。

- *ステートフル* な認証では、ユーザーがログインするときに一意のセッションIDが生成されます。後続のrequestでは、このセッションIDがサーバーに格納されたユーザーの詳細情報を参照するために機能します。セッションIDは *opaque* であり、ユーザーデータは含まれていません。

- *ステートレス* な認証では、すべてのユーザーの識別情報はクライアント側のトークンに格納されます。トークンは任意のサーバーまたはマイクロサービスに送信され、サーバー上でセッション状態を維持する必要はありません。ステートレスな認証は、ユーザーのログイン時にトークンを生成、署名し、トークンを暗号化する認証サーバーに組み込まれることがよくあります。

Webアプリケーションは、通常、クライアント側のCookieに格納されているランダムなセッションIDでステートフルな認証を行います。モバイルアプリでも同様の方法でステートフルなセッションを使用することがありますが、ステートレストークンベースのアプローチがさまざまな理由で普及しています。

- セッション状態をサーバーに保存する必要がなくなり、スケーラビリティとパフォーマンスが向上する。
- トークン方式を利用した場合、開発者は認証をアプリケーションから切り離すことができる。トークンは認証サーバーによって生成され、認証スキームがシームレスに変更できる。

モバイルセキュリティテスターとして、両方のタイプの認証に精通している必要があります。

### Verifying that Appropriate Authentication is in Place

認証に対する検証は、これさえやっておけば大丈夫というようなものはありません。アプリケーションの認証アーキテクチャを検証する際には、まず、使用されている認証方法がコンテキストに応じたものであるかを検証する必要があります。認証は、以下の1つまたは複数の要素に基づいて行うことができます。

- ユーザーが知っているもの（パスワード、PIN、パターンなど）
- ユーザーが持っているもの（SIMカード、ワンタイムパスワードジェネレータ、またはハードウェアトークン）
- ユーザの生体認証特性（指紋、網膜、声）

モバイルアプリケーションによって実装される認証手順の数は、機能やアクセスされたリソースの機密性によって決まります。認証機能を確認する際は、業界のベストプラクティスを参照してください。ユーザ名/パスワードでの認証(合理的なパスワードポリシーと組み合わせて)は、一般に、ユーザログインがあり、非常に機微といえるような情報までは扱わないアプリであれば、それで十分だと考えられています。この形式の認証は、ほとんどのソーシャルメディアアプリで使用されています。

機密情報を扱うようなアプリの場合、2つめの認証要素を追加するのが適切です。これには、機密情報（クレジットカード番号など）へアクセスするようなアプリケーションや、ユーザーが送金できるようなアプリが挙げられます。一部の業界では、これらのアプリも一定の基準に準拠している必要があります。たとえば、金融アプリケーションは、PCI DSS（Payment Card Industry Data Security Standard）、Gramm Leech Bliley Act、SOX（Sarbanes-Oxley Act）の順守が必要です。米国のヘルスケア部門のコンプライアンスに関する考慮事項には、医療保険の相互運用性と説明責任に関する法令(HIPAA)および患者安全規則が含まれます。

また、[OWASP Mobile AppSec Verification Standard](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x09-V4-Authentication_and_Session_Management_Requirements.md "OWASP MASVS: Authentication")をガイドラインとして使用することもできます。重要度の低いアプリケーション("Level 1")の場合、MASVSは次の認証要件を挙げています。

- アプリケーションがリモートサービスへのアクセスをユーザーに提供する場合、ユーザー名/パスワード認証などの許容される形式の認証がリモートエンドポイントで実行される。
- パスワードポリシーが存在し、リモートエンドポイントで強制される。
- 誤った認証情報が過度に送信された場合、リモートエンドポイントはExponential Backoffを実装するか、ユーザーアカウントを一時的にロックする。

機密情報を扱うようなアプリ("Level 2")の場合、MASVSは以下を追加します：

- リモートエンドポイントに2つめの認証要素が存在し、2要素認証が適用される。
- 機密データやトランザクションを処理するアクションを有効にするには、ステップアップ認証が必要。
- アプリはログイン時に、自らのアカウントでの最近の行動をユーザーに通知する。

#### 2-Factor Authentication and Step-up Authentication

2要素認証（2FA）は、機密な個人のデータにアクセスするアプリの標準的な対策です。一般的な実装では、第1要素にパスワードを使用し、第2要素に以下のいずれかを使用します。

- SMSによるワンタイムパスワード（SMS-OTP）
- 電話通知によるワンタイムコード
- ハードウェアまたはソフトウェアトークン
- PKIとローカル認証を組み合わせたプッシュ通知

第2要素の認証は、ログイン時またはユーザのセッションの後で実行できます。たとえば、ユーザー名とPINを使用して銀行アプリにログインした後、ユーザーは機密性の低いタスクを実行する権限が与えられます。そして、ユーザが銀行振込の実行を試みると、第2要素（「ステップアップ認証」）での認証が必要となります。

#### Transaction Signing with Push Notifications and PKI

トランザクション署名は、重要なトランザクションを行う際にユーザーの承認を必要とします。 非対称暗号方式は、トランザクション署名を実装する最善の方法です。 このアプリは、ユーザーがサインアップするときに公開鍵/秘密鍵のペアを生成し、公開鍵をバックエンドに登録します。 秘密鍵は端末のキーストアに安全に格納されます。 トランザクションを承認するために、バックエンドは、トランザクションデータを含むプッシュ通知をモバイルアプリケーションに送信します。 ユーザーは、トランザクションを確認または拒否するように求められます。 確認の後、（PINまたは指紋を入力することによって）ユーザーはキーチェーンのロックを解除するように求められ、データはユーザーの秘密鍵で署名されます。 署名されたトランザクションはサーバーに送信され、サーバーはユーザーの公開鍵で署名を検証します。

#### Supplementary Authentication

認証スキームは、以下のような情報を用いた[passive contextual authentication](https://pdfs.semanticscholar.org/13aa/7bf53070ac8e209a84f6389bab58a1e2c888.pdf "Best Practices for Step-up Multi-factor Authentication")によって補足されます。

- 位置情報
- IPアドレス
- 時刻
- 使用されているデバイス

理想的には、このようなシステムでは、ユーザーのコンテキストを以前に記録されたデータと比較して、アカウントの不正使用または潜在的な詐欺を示す可能性のある異常を特定します。 このプロセスはユーザーにとって透過的ですが、攻撃者にとって強力な阻害要因になります。

### Testing Authentication

認証と認可のテストは以下のような手順となります。

- アプリケーションが使用する追加の認証要素を特定する。
- 重要な機能を提供するすべてのエンドポイントを見つける。
- 追加要素がすべてのサーバー側エンドポイントで厳密に実施されていることを確認する。

認証バイパスの脆弱性は、サーバー上で認証状態が一貫して実行されていない場合、およびクライアントが状態を改ざんしうる場合に発生します。バックエンドサービスはモバイルクライアントからの要求を処理している間は、リソースが要求されるたびにユーザーがログインし、許可されていることを確認してから、一貫して権限チェックを実行する必要があります。

[OWASP Web Testing Guide](https://www.owasp.org/index.php/Testing_for_Bypassing_Authentication_Schema_%27OTG-AUTHN-004%29 "Testing for Bypassing Authentication Schema (OTG-AUTHN-004)")の次の例を参照してください。この例では、WebリソースにURLでアクセスし、認証ステートをGETパラメータで渡します。

```
http://www.site.com/page.asp?authenticated=no
```

クライアントは、リクエストとともに送信されたGETパラメータを任意に変更することができます。クライアントが `authenticated`パラメータの値をyesに変更して認証を回避することを防ぐことはできません。

これはおそらく現実ではなかなか見つからない単純な例ですが、プログラマーは、認証状態を維持するために、Cookieなどの"隠された"クライアント側のパラメータに依存することがあります。彼らは、これらのパラメータは改ざんできないと考えています。たとえば、次の[classic vulnerability in Nortel Contact Center Manager](http://seclists.org/bugtraq/2009/May/251)を考えてみましょう。Nortelのアプライアンスの管理用Webアプリケーションは、ログインしたユーザーに管理者権限を与える必要があるかどうかを、cookie "isAdmin"に依存していました。したがって、次のようにCookieの値を設定するだけで管理者アクセスを取得することができました：

```
isAdmin=True
```

セキュリティ専門家は、セッションベースの認証を使用し、セッションデータをサーバー上でのみ維持することを推奨していました。これにより、クライアント側がセッション状態を改ざんすることを防ぐことができます。しかし、セッションベース認証の代わりにステートレス認証を使用することのポイントは、サーバー上にセッション状態を *持たない* ことです。代わりに、状態はクライアント側のトークンに格納され、要求ごとに送信されます。この場合、`isAdmin`のようなクライアント側のパラメータを見ることは当然のことなのです。。

改ざんを防止するために、暗号化シグネチャがクライアント側のトークンに追加されます。もちろん、これは悪化する可能性もあり、一般的なステートレス認証の実装は攻撃に対して脆弱です。たとえば、いくつかのJSON Webトークン(JWT)の署名検証は、[署名タイプを "なし"に設定することで無効にすることができます](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)。この攻撃については、"Testing JSON Web Tokens"の章で詳しく説明します。

#### Best Practices for Passwords

パスワードが認証に使用される場合、パスワード強度は重要な問題です。パスワードポリシーは、エンドユーザーが準拠すべき要件を定義します。パスワードポリシーでは、通常、パスワードの長さ、パスワードの複雑さ、およびパスワードのトポロジを指定します。"強力な"パスワードポリシーは、手動または自動のパスワードクラッキングを困難または不可能にします。

**パスワードの長さ**

- 最小パスワード長(10文字)を強制する必要があります。
- ユーザーがパスフレーズを作成できないようにするため、最大パスワードの長さを短くしないでください。標準的な最大長は128文字です。

**パスワードの複雑さ**

パスワードは、次の4つの複雑さのルールのうち少なくとも3つを満たす必要があります。

1. 少なくとも1桁以上の大文字(A〜Z)
2. 少なくとも1桁以上の小文字(a-z)
3. 少なくとも1桁以上の数字(0〜9)
4. 少なくとも1桁以上の特殊文字

パスワードポリシーとパスワードの複雑さの要件が存在することを確認し、[OWASP Authentication Cheat Sheet](https://www.owasp.org/index.php/Authentication_Cheat_Sheet#Password_Complexity "Password Complexity")でも確認してください。ソースコード内のすべてのパスワード関連の機能を識別し、それぞれに検証チェックが実行されていることを確認します。パスワード検証機能を確認し、パスワードポリシーに違反するパスワードが拒否されていることを確認します。

正規表現は、多くの場合、パスワード規則を適用するために使用されます。たとえば、[JavaScript implementation by NowSecure](https://github.com/nowsecure/owasp-password-strength-test "NowSecure - OWASP Password Strength Test")では、正規表現を使用して、長さと文字の種類などを検証します。以下はコードの抜粋です。

```javascript
function(password) {
  if (password.length < owasp.configs.minLength) {
    return 'The password must be at least ' + owasp.configs.minLength + ' characters long.';
  }
},

// forbid repeating characters
function(password) {
  if (/(.)\1{2,}/.test(password)) {
    return 'The password may not contain sequences of three or more repeated characters.';
  }
},

function(password) {
  if (!/[a-z]/.test(password)) {
    return 'The password must contain at least one lowercase letter.';
  }
},

// require at least one uppercase letter
function(password) {
  if (!/[A-Z]/.test(password)) {
    return 'The password must contain at least one uppercase letter.';
  }
},

// require at least one number
function(password) {
  if (!/[0-9]/.test(password)) {
    return 'The password must contain at least one number.';
  }
},

// require at least one special character
function(password) {
  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'The password must contain at least one special character.';
  }
},
```

詳細については、[OWASP Authentication Cheat Sheet](https://www.owasp.org/index.php/Authentication_Cheat_Sheet#Implement_Proper_Password_Strength_Controls "OWASP Authentication Cheat Sheet")を参照してください。[zxcvbn](https://github.com/dropbox/zxcvbn "zxcvbn")は、パスワード強度の推定に使用できる共通ライブラリです。多くのプログラミング言語で使用できます。

##### Running a Password Dictionary Attack

自動パスワード推測攻撃は、多数のツールを使用して実行できます。HTTP(S)サービスの場合、中間プロキシを使用することは実行可能な選択肢です。たとえば、[Burp Suite Intruder](https://portswigger.net/burp/help/intruder_using.html "Using Burp Suite Intruder")を使用して、辞書攻撃とブルートフォース攻撃の両方を実行できます。

- Burp Suiteを起動します。
- 新しいプロジェクトを作成します(または既存のプロジェクトを開きます)。
- HTTP/HTTPSプロキシとしてBurpを使用するようモバイルデバイスを設定します。モバイルアプリにログインし、バックエンドサービスに送信された認証リクエストを傍受します。
- 'Proxy/HTTP History'タブでこのリクエストを右クリックし、コンテキストメニューの'Send to Intruder'を選択します。
- Burp Suiteの'Intruder'タブを選択します。
- 'Target'、'Positions'、'Options'タブのすべてのパラメータが適切に設定されていることを確認し、'Payload'タブを選択します。
- 試してみるパスワードのリストをロードまたはアップロードします。これであなたは攻撃を開始する準備ができました！

![List of passwords in Burp Suite](Images/Chapters/0x04e/BurpIntruderInputList.gif)

- [Start attack]ボタンをクリックして認証を攻撃します。

新しいウィンドウが開きます。攻撃リクエストは順次送信され、それらはリストのパスワードに対応しています。レスポンス(長さ、ステータスコード...)に関する情報は、リクエストごとに提供され、成功したかどうかを区別できます。

![A successful attack in Burp Suite](Images/Chapters/0x04e/BurpIntruderSuccessfulAttack.gif)

この例では、長さ(password = "P@ssword1")で成功した試みを識別できます。

> ヒント：テストアカウントの正しいパスワードをパスワードリストの末尾に追加します。リストには25を超えるパスワードを設定しないでください。アカウントがロックせずに攻撃が完了した場合、そのアカウントはブルートフォース攻撃から保護されていないことを意味します。

##### Login Throttling

同じユーザー名で短時間試行されたログインのカウンターと最大試行回数に達した後にログインの試行を防ぐ方法という、大量ログイン対策についてのソースコードをチェックします。承認されたログインの試行後、エラーカウンタをリセットする必要があります。

ブルートフォース対策を実装するときは、次のベストプラクティスを守ってください。

- ログイン試行が数回失敗した場合、ターゲットアカウントは(一時的または永続的)ロックされ、以降のログイン試行は拒否されます。
- 一時的なアカウントロックには、一般的に5分のアカウントロックが使用されます。
- クライアント側のコントロールは簡単に回避されるため、サーバー側で実装する必要があります。
- 認証されていないログイン試行は、特定のセッションではなく、対象のアカウントに対してカウントされる必要があります。

この他のブルートフォース攻撃への軽減策は、OWASPの[Blocking Brute Force Attacks](https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks "OWASP - Blocking Brute Force Attacks")に記載されています。

OTP認証を使用する場合は、ほとんどのOTPが短い数値であることを考慮してください。この段階で失敗したN回の試行の後にアカウントがロックされていない場合、攻撃者はOTPの寿命で範囲内の値をブルートフォースすることによって、第2要素を回避できます。72時間以内に30秒のタイムステップで6桁の値が一致する確率は90％以上です。

### Testing Stateful Session Management

ステートフル(または"セッションベース")認証は、クライアントとサーバーの両方の認証レコードによって特徴付けられます。認証フローは以下のとおりです。

1. アプリケーションは、ユーザーの資格情報を含むリクエストをバックエンドサーバーに送信します。
2. サーバーが資格情報を検証し、有効な場合、サーバーはランダムなセッションIDとともに新しいセッションを作成します。
3. サーバーは、セッションIDを含むレスポンスをクライアントに送信します。
4. クライアントはすべての後続のリクエストにセッションIDを付して送信します。サーバーはセッションIDを検証し、関連するセッションレコードを取得します。
5. ユーザーがログアウトすると、サーバー側のセッションレコードが破棄され、クライアントはセッションIDを破棄します。

セッションが不適切に管理されると、さまざまな攻撃に対して脆弱であり、正当なユーザーのセッションを危険にさらし、攻撃者がユーザーになりすます可能性があります。これにより、データが失われ、機密性が損なわれ、違法行為が発生する可能性があります。

#### Session Management Best Practices

重要な情報または機能を提供するサーバー側のエンドポイントを特定し、一貫性のある認証が行われているかを確認します。バックエンドサービスは、ユーザーのセッションIDまたはトークンを確認し、ユーザーがリソースにアクセスするための十分な権限を持っていることを確認する必要があります。セッションIDまたはトークンが見つからないか無効である場合、そのリクエストは拒否されなければなりません。

以下を確認してください：

- セッションIDはサーバー側でランダムに生成されます。
- セッションIDは簡単に推測できません(適切な長さとエントロピーを使用してください)。
- セッションIDは常にセキュアな接続(HTTPSなど)で交換されます。
- モバイルアプリはセッションIDを永続ストレージに保存しません。
- サーバーは、ユーザーが特権アプリケーション要素にアクセスしようとするたびにセッションを検証します（セッションIDは有効で、適切な許可レベルに対応していなければなりません）。
- セッションはサーバー側で終了され、タイムアウトまたはユーザーがログアウトした後にモバイルアプリ内で削除されます。

認証は最初から実装するのではなく、実績のあるフレームワークの上に構築する必要があります。多くの一般的なフレームワークは、既製の認証およびセッション管理機能を提供しています。アプリケーションでフレームワークAPIを使用して認証する場合は、フレームワークのセキュリティドキュメントでベストプラクティスを確認してください。共通のフレームワークのセキュリティガイドは、次のリンクから入手できます。

- [Spring (Java)](https://projects.spring.io/spring-security "Spring (Java)")
- [Struts (Java)](https://struts.apache.org/docs/security.html "Struts (Java)")
- [Laravel (PHP)](https://laravel.com/docs/5.4/authentication "Laravel (PHP)")
- [Ruby on Rails](https://guides.rubyonrails.org/security.html "Ruby on Rails")

サーバサイド認証をテストするための素晴らしいリソースは、OWASP Web Testing Guideです。具体的には、[Testing Authentication](https://www.owasp.org/index.php/Testing_for_authentication)と[Testing Session Management](https://www.owasp.org/index.php/Testing_for_Session_Management)の章を参照してください。

##### Session Timeout

一般的なフレームワークでは、設定オプションを使用してセッションタイムアウトを設定できます。このパラメータは、フレームワークのドキュメントで指定されているベストプラクティスに従って設定する必要があります。推奨されるタイムアウトは、アプリケーションの重要度に応じて、10分から2時間程度です。

セッションタイムアウト設定の例については、フレームワークのドキュメントを参照してください。

- [Spring (Java)](https://docs.spring.io/spring-session/docs/current/reference/html5/ "Spring (Java)")
- [Ruby on Rails](https://guides.rubyonrails.org/security.html#session-expiry "Ruby on Rails")
- [PHP](https://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime "PHP")
- [ASP.Net](https://goo.gl/qToQuL "ASP.NET")

#### Dynamic Analysis

動的分析を使用して、すべてのリモートエンドポイントで一貫した認可が行われているかを検証することができます。まず、アプリケーションを手動または自動でクロールして、すべての特権機能とデータが安全であることを確認し、有効なセッションIDが必要かどうかを確認します。その際、プロキシにリクエストを記録します。

次に、以下のようにセッションIDを操作しながらクロールされたリクエストを再送します。

- セッションIDを無効にします（たとえば、セッションIDに何らかの値を追加する、またはリクエストからセッションIDを削除するなど）。
- セッションIDが変更されたかどうかを確認するには、ログアウトして再度ログインします。
- ログアウト後にセッションIDを再使用してみてください。

セッションのタイムアウトを確認するには：

1. アプリケーションにログインします。
2. 認証が必要な2つの操作を実行します。
3. 期限が切れるまでセッションを利用した通信などが行われないようにします。セッションが終了したら、同じセッションIDを使用して認証が必要な機能にアクセスします。

##### Verifying that 2FA is Enforced

中間プロキシを使用してリモートエンドポイントに送信されたリクエストをキャプチャしながら、アプリケーションを広範囲(すべてのUIフローを通る)で使用します。次に、2要素認証を必要とするエンドポイント(例えば、金融取引の実行)に対するリクエストを、まだ、2要素認証またはステップアップ認証によって権限を付与されていないトークンやセッションIDを利用して再送します。エンドポイントが2要素認証またはステップアップ認証後にのみアクセス可能なデータを送り返している場合、そのエンドポイントで認証チェックが適切に実装されていないことになります。

セッション管理のテストの詳細については、[OWASP Testing Guide](https://www.owasp.org/index.php/Testing_for_Session_Management "OWASP Testing Guide V4 (Testing for Session Management)") を参照してください。

### Testing Stateless (Token-Based) Authentication

トークンベースの認証は、各HTTPリクエストに署名されたトークン(サーバーで検証済み)を送信することによって実現しています。最も一般的に使用されるトークン形式は、(https://tools.ietf.org/html/rfc7519)で定義されているJSON Webトークンです。JWTは、完全なセッション状態をJSONオブジェクトとしてエンコードすることができます。したがって、サーバーはセッションデータまたは認証情報を格納する必要はありません。

JWTトークンは、ドットで区切られた3つのBase64でエンコードされたブロックで構成されています。次の例は、[Base64-encoded JSON Web Token](https://jwt.io/#debugger "JWT Example on jwt.io")を示しています。

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

*ヘッダー* は、通常、JWTであるとするトークンのタイプと、署名を計算するために使用するハッシュアルゴリズムの2つの部分で構成されます。上記の例では、ヘッダーは次のようにデコードされます。

```
{"alg":"HS256","typ":"JWT"}
```

トークンの2番目の部分は、いわゆる *ペイロード* であり、これはいわゆるクレームを含んでいます。クレームとは、エンティティ(通常はユーザー)と追加のメタデータに関するステートメントです。例えば：

```
{"sub":"1234567890","name":"John Doe","admin":true}
```

署名は、JWTヘッダーで指定されたアルゴリズムを、エンコードされたヘッダー、エンコードされたペイロード、および秘密の値に適用することによって作成されます。たとえば、HMAC SHA256アルゴリズムを使用する場合、署名は次のように作成されます。

```
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
```

secretの値は、認証サーバーとバックエンドサービス間でのみ共有され、クライアントはそれを知りえません。これは、トークンが正当な認証サービスから取得されたことを証明します。また、クライアントがトークンに含まれるクレームを改ざんするのを防ぎます。

#### Static Analysis

サーバーとクライアントが使用するJWTライブラリーを特定します。使用しているJWTライブラリに既知の脆弱性が存在するかどうか調査します。

実装がJWTの[best practices](https://stormpath.com/blog/jwt-the-right-way "JWT the right way")に準拠していることを確認します。

- トークンを含んでいるすべてのリクエストがHMACでチェックされていることを確認します。
- プライベート署名鍵またはHMAC秘密鍵の場所を確認します。キーはサーバー上に残り、クライアントと決して共有しないでください。発行者と検証者だけが利用可能な状態にしてください。
- 個人識別可能な情報などの機密データがJWTに埋め込まれていないことを確認します。なんらかの理由で、アーキテクチャがトークンにそのような情報を送信する必要がある場合は、ペイロードの暗号化が適用されていることを確認してください。[OWASP JWT Cheat Sheet](https://goo.gl/TGzA5z "JSON Web Token (JWT) Cheat Sheet for Java")のJavaでの実装例を参照してください。
- JWTに一意の識別子を与える `jti`(JWT ID)クレームで再生攻リプレイアタックが対処されていることを確認します。
- トークンがモバイル端末にKeyChain(iOS)やKeyStore(Android)などのように安全に保存されていることを確認します。

##### Enforcing the Hashing Algorithm

攻撃者は、トークンを変更し、'none'キーワードを使用して署名アルゴリズムを変更し、トークンの完全性がすでに検証済みであることを示すようにして、これを実行します。上記リンクで説明されているように、トークンを処理したライブラリの中には、noneアルゴリズムで署名されたトークンであるかのように署名されたトークンを処理するものもあります。

たとえば、Javaアプリケーションでは、検証コンテキストを作成するときに期待されるアルゴリズムを明示的に要求する必要があります。

```java
// HMAC key - シリアライゼーションやJVMメモリ内の文字列として保存されることを防ぎます
private transient byte[] keyHMAC = ...;

//HMAC-256 hmacの生成に明示的な使用が要求されるトークンの検証コンテキストを作成する。

JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC)).build();

//トークンを検証する。検証に失敗した場合は例外を投げる。

DecodedJWT decodedToken = verifier.verify(token);
```

##### Token Expiration

一度署名されると、署名のキーが変更されない限り、ステートレスな認証トークンは永久に有効です。トークンを制限する一般的な方法は有効期限を設定することです。トークンに[期限切れクレーム](https://tools.ietf.org/html/rfc7519#section-4.1.4 "RFC 7519")が含まれていることを確認し、バックエンドでは期限切れのトークンを有効に扱いません。

トークンを付与する一般的な方法は、[アクセストークンとリフレッシュトークン](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/ "Refresh tokens & access tokens")の組み合わせです。ユーザーがログインすると、バックエンドサービスは短命の *アクセストークン* と長命の *リフレッシュトークン* を発行します。アクセストークンが期限切れになった場合、アプリケーションはリフレッシュトークンを使用して新しいアクセストークンを取得できます。

機密データを扱うアプリケーションの場合、リフレッシュトークンが妥当な期間を過ぎると期限切れになることを確認してください。次のコード例は、リフレッシュトークンの発行日を確認するリフレッシュトークンAPIを示しています。トークンが14日以上経過していない場合は、新しいアクセストークンが発行されます。それ以外の場合、アクセスは拒否され、ユーザーは再度ログインするように要求されます。

```Java
 app.post('/refresh_token', function (req, res) {
  //既存のトークンを確認する
  var profile = jwt.verify(req.body.token, secret);

  // 14日以上経過している場合、強制的にログインをさせます
  if (profile.original_iat - new Date() > 14) { // iat == issued at
    return res.send(401); // 再ログイン
  }

  //ユーザーがまだ存在するかどうか、または承認が取り消されていないかどうかを確認する
  if (!valid) return res.send(401); // re-logging

  //新しいトークンを発行する
  var refreshed_token = jwt.sign(profile, secret, { expiresInMinutes: 60*5 });
  res.json({ token: refreshed_token });
});
```

#### Dynamic Analysis

動的分析を実行しながら、次のJWTの脆弱性を調査します。

- [非対称アルゴリズム](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/ "Critical Vulnerabilities in JSON Web Token")の使用：
  * JWTは、RSAまたはECDSAのようないくつかの非対称アルゴリズムを提供しています。これらのアルゴリズムを使用すると、トークンは秘密鍵で署名され、公開鍵は検証に使用されます。サーバーが非対称アルゴリズムで署名されたトークンを予定しているところにHMACで署名されたトークンを受信した場合、公開鍵はHMACの秘密鍵として扱われます。公開鍵は悪用され、HMAC秘密鍵として使用されてトークンに署名することができます。
- クライアント上のトークンストレージ：
  * JWTを使用するモバイルアプリのトークンの保存場所を確認する必要があります。
- 署名鍵のクラッキング：
  * トークン署名は、サーバー上の秘密鍵を介して作成されます。JWTを取得したら、[秘密鍵をオフラインでブルートフォースする](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/ "Attacking JWT Authentication")ツールを選択します。
- 情報開示：
  * Base64でエンコードされたJWTをデコードし、送信するデータの種類とそのデータが暗号化されているかどうかを調べます。

また、[OWASP JWT Cheat Sheet](https://goo.gl/TGzA5z "JSON Web Token (JWT) Cheat Sheet for Java")もチェックしてください。

##### Tampering with the Hashing Algorithm

トークンヘッダの `alg`属性を修正し、` HS256`を削除し、`none`に設定し、空の署名（signature =""など）を使用してください。このトークンを使用して、リクエストで再送します。一部のライブラリは、noneアルゴリズムで署名されたトークンを、検証済みの署名付きの有効なトークンとして扱います。これにより、攻撃者は独自の「署名済み」トークンを作成できます。

### User Logout and Session Timeouts

セッション識別子とトークンの存続期間を最小限に抑えることで、アカウントのハイジャックが成功する可能性が低くなります。このテストケースの目的は、ログアウト機能を検証し、クライアントとサーバーの両方でセッションを効果的に終了し、ステートレストークンを無効にするかどうかを判断することです。

サーバー側のセッションを破棄しないことは、最も一般的なログアウト機能の実装エラーの1つです。このエラーは、ユーザーがアプリケーションからログアウトした後でも、セッションまたはトークンを有効に保ちます。有効な認証情報を取得した攻撃者は引き続きそのアカウントを使用してユーザーアカウントを乗っ取ることができます。

多くのモバイルアプリは、ステートレス認証を実装することで、顧客にとって不便であるという理由で、ユーザーを自動的にはログアウトさせません。アプリケーションには引き続きログアウト機能が必要です。ベストプラクティスに従って実装し、クライアントおよびサーバー上のアクセスおよびリフレッシュトークンを破棄する必要があります。そうしないと、リフレッシュトークンが無効化されていないときに認証をバイパスできます。

##### Verifying Best Practices

サーバーコードが利用可能な場合は、ログアウト機能が終了してセッションが終了していることを確認してください。この検証はテクノロジによって異なります。適切なサーバー側のログアウト時のセッション終了の例を以下に示します。

- [Spring (Java)](https://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html "Spring (Java)")
- [Ruby on Rails](https://guides.rubyonrails.org/security.html "Ruby on Rails")
- [PHP](https://php.net/manual/en/function.session-destroy.php "PHP")

ステートレス認証でアクセストークンとリフレッシュトークンを使用する場合は、それらをモバイルデバイスから削除する必要があります。[リフレッシュトークンはサーバー上で無効化される必要があります。](https://auth0.com/blog/blacklist-json-web-token-api-keys/ "Blacklisting JSON Web Token API Keys")。

#### Dynamic Analysis

動的アプリケーション分析には、中間プロキシを使用します。 ログアウトが適切に実装されているかどうかを確認するには、次の手順を実行します。

1. アプリケーションにログインします。
2. アプリケーション内での認証が必要な操作を2回実行します。
3. ログアウトします。
4. 中間プロキシ(たとえば、Burp Repeater)を使用して、手順2の操作の1つを再送します。これにより、手順3で無効化されたセッションIDまたはトークンを持つリクエストがサーバーに送信されます。

ログアウト機能がサーバーに正しく実装されている場合は、エラーメッセージまたはログインページへのリダイレクトがクライアントに返されます。一方、手順2で取得したのと同じレスポンスを受け取った場合でも、トークンまたはセッションIDは有効であり、サーバー上で正しく終了していません。
OWASP Webテストガイド([OTG-SESS-006](https://www.owasp.org/index.php/Testing_for_logout_functionality "OTG-SESS-006"))には、詳細な説明とテストケースが含まれています。

### Testing OAuth 2.0 Flows

[OAuth 2.0は、APIとウェブ対応アプリケーションのネットワークを介して認証決定を伝えるための委任プロトコルを定義しています。](https://oauth.net/articles/authentication/ "OAuth 2.0 delegation protocols")。これは、ユーザー認証アプリケーションを含むさまざまなアプリケーションで使用されます。

OAuth2の一般的な使用方法は次のとおりです。

- アカウントを使用してオンラインサービスにアクセスする許可をユーザから得る。
- ユーザーに代わってオンラインサービスの認証を行う。
- 認証エラーの処理。

OAuth 2.0によると、ユーザーのリソースへのアクセスを求めるモバイルクライアントは、まずユーザーに *認証サーバー* の認証を求める必要があります。ユーザーの承認により、認証サーバーはトークンを発行して、ユーザーの代わりにアプリケーションを動作させることができます OAuth2の仕様では、特定の種類の認証またはアクセストークンの形式は定義されていないことに注意してください。

OAuth 2.0では、4つの役割が定義されています。

- リソースオーナー: アカウント所有者
- クライアント: アクセストークンを使用してユーザーのアカウントにアクセスするアプリケーション
- リソースサーバー: ユーザーアカウントをホストする
- 認証サーバー: ユーザーの認証情報を確認し、アプリケーションへアクセストークンを発行する

注：APIは、リソースオーナーと認証サーバーの役割の両方を満たします。したがって、両方をAPIと呼ぶことにします。

![Abstract Protocol Flow](Images/Chapters/0x04e/abstract_oath2_flow.png)

この図の[手順の詳細](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2 "An Introduction into OAuth2")は、次のとおりです。

1. アプリケーションは、サービスリソースにアクセスするためのユーザー認証を要求します。
2. ユーザーがリクエストを承認すると、アプリケーションは認証が付与されます。認証の付与は、いくつかの形式(明示的、暗黙的など)をとることができます。
3. アプリケーションは、認証の付与とともに自身の識別情報を提示することによって、認証サーバー(API)にアクセストークンをリクエストします。
4. アプリケーションの識別情報が受け付けられ、付与された認証情報が有効である場合、認証サーバー(API)はアプリケーションへのアクセストークンを発行して認可プロセスを完了します。アクセストークンは、コンパニオンリフレッシュトークンを有することができる。
5. アプリケーションは、リソースサーバー(API)からリソースをリクエストし、認証用のアクセストークンを提示します。アクセストークンは、いくつかの方法で(例えば、ベアラトークンとして)使用されても問題ありません。
6. アクセストークンが有効な場合、リソースサーバー(API)はリソースをアプリケーションに提供します。

#### OAUTH 2.0 Best Practices

次のベストプラクティスが実行されていることを確認します。

ユーザーエージェント：

- ユーザには、信頼性を視覚的に確認する手段(例えば、TLS(Transport Layer Security)の確認、ウェブサイトのメカニズムなど)がある必要があります。
- 中間者攻撃を防ぐために、クライアントは、接続が確立されたときにサーバーが提示した公開鍵でサーバーの完全修飾ドメイン名を検証する必要があります。

Grant Type：

- ネイティブアプリの場合、暗黙の許可の代わりにコード許可を使用する必要があります。
- コード認可を使用する場合、コード認可を保護するためにPKCE(コード交換のための証明鍵)を実装する必要があります。サーバーもそれを実装していることを確認してください。
- auth "コード" は短命で、受け取った直後に使用する必要があります。認証コードが一時メモリにのみ存在し、保存またはログに記録されていないことを確認します。

クライアントの秘密：

- クライアントが偽装されている可能性があるため("client_id" はすでに証明として機能している)、共有秘密なものを使用してクライアントのIDを証明してはいけません。クライアントの秘密を使用する場合は、それらが安全なローカルストレージに格納されていることを確認してください。

エンドユーザーの資格情報：

- TLSなどのトランスポート層方式を使用して、エンドユーザ資格情報の送信を保護する。

トークン：

- アクセストークンを一時メモリに保持する。
- アクセストークンは、暗号化された接続を介して送信する必要があります。
エンドツーエンドの機密性が保証されていない場合、またはトークンが機密情報またはトランザクションにアクセスできる場合に、アクセストークンの範囲と期間を短縮する。
- トークンを盗まれた攻撃者は、アクセストークンをベアラトークンとして使用してクライアントを特定することができない場合、トークンを盗んだ攻撃者が自分のスコープとそのリソースにアクセスできることを覚えておいてください。
- 安全なローカルストレージにリフレッシュトークンを格納する。彼らは長期的な資格です。

##### External User Agent vs. Embedded User Agent

OAuth2認証は、外部のユーザーエージェント（ChromeやSafariなど）やアプリ内で実行できます（アプリに埋め込まれたWebViewや認証ライブラリなど）。どちらのモードも本質的に「より良い」ものではなく、どちらのモードを選択するかはコンテキストによって異なります。

*外部ユーザーエージェントを使用する* のは、ソーシャルメディアアカウント(Facebook、Twitterなど)と対話する必要があるアプリの選択方法です。この方法の利点は次のとおりです。

- ユーザーの資格情報が直接アプリケーションに公開されることはありません。これにより、ログインプロセス中にアプリがクレデンシャルを取得できないことが保証されます（「クレデンシャルフィッシング」）。

- 認証ロジックをアプリ自体に追加する必要はほとんどなく、コーディングエラーを防止します。

負の面では、ブラウザの動作を制御する方法はありません（たとえば、証明書のピン設定を有効にする）。

閉鎖されたエコシステム内で動作するアプリケーションでは、*組み込み認証* が最適です。たとえば、OAuth2を使用して銀行の認証サーバーからアクセストークンを取得し、多数のマイクロサービスにアクセスするために使用される銀行アプリケーションを考えてみましょう。その場合、資格情報フィッシングは実行可能なシナリオではありません。外部コンポーネントを信頼するのではなく、慎重に確保された銀行アプリケーションに認証プロセスを維持することが望ましいでしょう。

#### Other OAuth2 Best Best Practices

その他のベストプラクティスと詳細情報については、次のソースドキュメントを参照してください。

- [RFC6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749 "RFC6749: The OAuth 2.0 Authorization Framework (October 2012)")
- [DRAFT - OAuth 2.0 for Native Apps](https://tools.ietf.org/html/draft-ietf-oauth-native-apps-12 "draft_ietf-oauth-native-apps-12: OAuth 2.0 for Native Apps (June 2017)")
- [RFC6819 - OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819 "RFC6819: OAuth 2.0 Threat Model and Security Considerations (January 2013)")

### Login Activity and Device Blocking

L2での保護を必要とするアプリケーションの場合、MASVSは以下のように述べています。"アプリケーションは、そのアカウントで行われたすべてのログインアクティビティを通知します。ユーザーはアカウントへのアクセスや特定のデバイスのブロックに使用されるデバイスの一覧を表示できます。" これは、さまざまなシナリオに分類できます。

1. アプリケーションは、そのアカウントが別のデバイスで使用された際に、プッシュ通知を行い、ユーザーにさまざまなアクティビティを通知します。ユーザーは、プッシュ通知を介してアプリを開いた後、このデバイスをブロックすることができます。
2. 前回のセッションが現在のものと異なる構成(例えば、位置情報やデバイス、アプリのバージョン)であった場合、アプリケーションはログイン後に直前のセッションに関する概要を通知します。ユーザは疑わしい活動を報告し、前のセッションで使用されたデバイスをブロックすることができます。
3. アプリケーションは、ログイン後の直前のセッションの概要を常に提供します。
4. アプリケーションには、ユーザーが監査ログを表示し、ログインできるさまざまなデバイスを管理できるセルフサービスポータルがあります。

すべての場合において、ペンテスターは、異なるデバイスが正しく検出されているかどうかを確認する必要があります。したがって、実際のデバイスへのアプリケーションのバインディングをテストする必要があります。たとえば、iOSでは開発者は `identifierForVendor`を使用して、Androidでは開発者は`Settings.Secure.ANDROID_ID`を使用してアプリケーションインスタンスを識別できます。iOS用のKeychainとAndroid用のKeyStoreのキーイング素材を使ったこのクワイエーターは、強力なデバイスバインディングを安心させることができます。次に、Pentesterは、異なるIPを使用している場合、異なる場所および/または異なるタイムスロットがすべてのシナリオで正しいタイプの情報をトリガーするかどうかをテストする必要があります。

最後に、デバイスのブロックは、アプリケーションの登録済みインスタンスをブロックし、認証がもはや許可されていないかどうかを調べることによって、テストする必要があります。
注意：L2保護を必要とするアプリケーションの場合は、新しいデバイスで最初に認証される前にユーザーに警告することをお勧めします。代わりに、アプリの2番目のインスタンスが登録されているときに既にユーザーに警告します。

### References

#### OWASP Mobile Top 10 2016

- M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

#### OWASP MASVS

- V4.1: "If the app provides users access to a remote service, some form of authentication, such as username/password authentication, is performed at the remote endpoint."
- V4.2: "If stateful session management is used, the remote endpoint uses randomly generated session identifiers to authenticate client requests without sending the user's credentials."
- V4.3: "If stateless token-based authentication is used, the server provides a token that has been signed with a secure algorithm."
- V4.4: "The remote endpoint terminates the existing stateful session or invalidates the stateless session token when the user logs out."
- V4.5: "A password policy exists and is enforced at the remote endpoint."
- V4.6: "The remote endpoint implements an exponential back-off or temporarily locks the user account when incorrect authentication credentials are submitted an excessive number of times."
- v4.7: "Sessions are invalidated at the remote endpoint after a predefined period of inactivity and access tokens expire."
- V4.9: "A second factor of authentication exists at the remote endpoint and the 2FA requirement is consistently enforced."
- V4.10: "Sensitive transactions require step-up authentication."
- v4.11: "The app informs the user of all login activities with their account. Users are able view a list of devices used to access the account, and to block specific devices"

#### CWE

- CWE-287 - Improper Authentication
- CWE-307 - Improper Restriction of Excessive Authentication Attempts
- CWE-308 - Use of Single-factor Authentication
- CWE-521 - Weak Password Requirements
- CWE-613 - Insufficient Session Expiration

##### Tools

- Free and Professional Burp Suite editions - https://portswigger.net/burp/
Important precision: The free Burp Suite edition has significant limitations . In the Intruder module, for example, the tool automatically slows down after a few requests, password dictionaries aren't included, and you can't save projects.
- [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
- [jwtbrute](https://github.com/jmaxxz/jwtbrute)
- [crackjwt](https://github.com/Sjord/jwtcrack/blob/master/crackjwt.py)
- [John the ripper](https://github.com/magnumripper/JohnTheRipper)
