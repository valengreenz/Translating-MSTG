## Testing Code Quality

モバイルアプリ開発者は、さまざまなプログラミング言語とフレームワークを使用しています。そのため、安全なプログラミング手法を無視すると、SQLインジェクション、バッファオーバーフロー、クロスサイトスクリプティング(XSS)などの一般的な脆弱性がアプリに顕在化することになります。

同じプログラミングのミスは、ある程度まではAndroidとiOSの両方のアプリに悪影響を与えうるため、ガイドの一般的なセクションで、一般的な脆弱性クラスの概要について説明しています。以降のセクションでは、OS固有のインスタンスについて説明し、軽減機能を活用していきます。

### Injection Flaws

*インジェクションの欠陥* は、ユーザーの入力値がバックエンドのクエリまたはコマンドに挿入されたときに発生するセキュリティ上の脆弱性カテゴリについて説明します。メタキャラクタを注入することにより、攻撃者は、コマンドまたはクエリの一部として解釈される悪意あるコードを実行できます。たとえば、SQLクエリを操作することにより、攻撃者は任意のデータベースレコードを取得したり、バックエンドデータベースのコンテンツを操作したりする可能性があります。

このタイプの脆弱性は、サーバーサイドで実行されるWebサービスでしばしば見られます。悪用される可能性のあるインスタンスもモバイルアプリ内に存在しますが、発生頻度はそれほど多くはなく、さらに攻撃対象領域も小さくなります。

たとえば、アプリがローカルのSQLiteデータベースをクエリ操作する場合、そのようなデータベースは通常機密データを格納しません(開発者が基本的なセキュリティプラクティスに従っているとした場合)。これはSQLインジェクションを実行不可能な攻撃ベクターにします。それにもかかわらず、悪用可能なインジェクションの脆弱性がしばしば発生します。つまり、適切な入力値検証はプログラマにとって必要なベストプラクティスなのです。

#### SQL Injection

*SQLインジェクション* 攻撃は、事前定義されたSQLコマンドの構文を模倣し、SQLコマンドを入力データに加えることを含みます。SQLインジェクション攻撃が成功すると、攻撃者はサーバーから与えられたアクセス権限に応じて、データベースの読み書きや、場合によっては管理コマンドを実行したりすることができます。

AndroidとiOSの両方のアプリは、ローカルデータストレージを制御し整理する手段としてSQLiteデータベースを使用しています。Androidアプリがユーザーの資格情報をローカルデータベースに格納することでローカルユーザー認証を実現していると仮定します(この例では、プログラミングの慣習としては見逃しがちです)。ログインすると、アプリはデータベースに照会して、ユーザーが入力したユーザー名とパスワードでレコードを検索します。

```java=
SQLiteDatabase db;

String sql = "SELECT * FROM users WHERE username = '" +  username + "' AND password = '" + password +"'";

Cursor c = db.rawQuery( sql, null );

return c.getCount() != 0;
```

さらに、攻撃者が「ユーザー名」と「パスワード」のフィールドに次の値を入力したとします。

```sql
username = 1' or '1' = '1
password = 1' or '1' = '1
```
これにより、次のクエリが生成されます。

```sql
SELECT * FROM users WHERE username='1' OR '1' = '1' AND Password='1' OR '1' = '1'
```

条件`'1' = '1'`は常に真と評価されるため、このクエリはデータベース内のすべてのレコードを返し、有効なユーザーアカウントが入力されていなくてもログイン関数は "true" を返します。

Ostorlabは、このSQLインジェクションのペイロードを使用したadbによって、Yahoo Weatherのモバイルアプリのsortパラメータに対する攻撃に成功しました。

```
$ adb shell content query --uri content://com.yahoo.mobile.client.android.weather.provider.Weather/locations/ --sort '_id/**/limit/**/\(select/**/1/**/from/**/sqlite_master/**/where/**/1=1\)'  

Row: 0 _id=1, woeid=2487956, isCurrentLocation=0, latitude=NULL, longitude=NULL, photoWoeid=NULL, city=NULL, state=NULL, stateAbbr=, country=NULL, countryAbbr=, timeZoneId=NULL, timeZoneAbbr=NULL, lastUpdatedTimeMillis=746034814, crc=1591594725

```

以下の`_id/**/limit/**/\(select/**/1/**/from/**/sqlite_master\)`を使ってペイロードをさらに単純化することができます。

このSQLインジェクションの脆弱性は、ユーザーがまだアクセスできない機密データは一切曝露しませんでした。この例では、adbを使用して脆弱なコンテンツプロバイダをテストする方法を示します。 Ostorlabはこれをさらに継承し、SQLiteクエリのWebページインスタンスを作成してから、SQLmapを実行してテーブルをダンプします。

```python

import subprocess
from flask import Flask, request

app = Flask(__name__)

URI = "com.yahoo.mobile.client.android.weather.provider.Weather/locations/"

@app.route("/")
def hello():

   method = request.values['method']
   sort = request.values['sort']
   sort = "_id/**/limit/**/(SELECT/**/1/**/FROM/**/sqlite_master/**/WHERE/**/1={})".format(sort)
   #sort = "_id/**/limit/**/({})".format(sort)

   p = subprocess.Popen(["adb","shell","content",method,"--uri","content://{}".format(URI),"--sort",'"{}"'.format(sort)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

   o, e = p.communicate()

   print "[*]SORT:{}".format(sort)
   print "[*]OUTPUT:{}".format(o)
   return "<html><divclass='output'>{}</div></html>".format(o)

if __name__=="__main__":
   app.run()

```

クライアントサイドのSQLインジェクションの実例は、Mark Woodsによって、QNAP NASストレージアプライアンス上で実行されているAndroidアプリ「Qnotes」および「Qget」で発見されました。これらのアプリはSQLインジェクションに対して脆弱なコンテンツプロバイダをエクスポートし、攻撃者がNASデバイスの認証情報を取得することを可能にしました。この問題の詳細な説明は[Nettitude Blog](https://blog.nettitude.com/uk/qnap-android-dont-provide "Nettitude Blog - QNAP Android: Don't Over Provide")にあります。

#### XML Injection

*XMLインジェクション* 攻撃では、攻撃者はXMLメタ文字を注入してXMLコンテンツを構造的に変化させます。これは、XMLベースのアプリケーションやサービスのロジックを危険に晒したり、攻撃者がコンテンツを処理するXMLパーサーの操作を悪用するために使用されます。

この攻撃の一般的なものは[XML Entity Injection (XXE)](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing)です。ここで、攻撃者はURIを含む外部エンティティ定義を入力XMLに挿入します。パース時に、XMLパーサーはURIで指定されたリソースにアクセスすることによって、攻撃者定義のエンティティを拡張します。解析アプリケーションの完全性により、最終的に攻撃者に与えられる機能が決定されます。悪意のあるユーザーは、ローカルファイルへのアクセス、任意のホストおよびポートへのHTTPリクエストのトリガー、[cross-site request forgery (CSRF)](https://goo.gl/UknMCj "Cross-Site Request Forgery (CSRF)")攻撃の実行が可能です。そして、サービス拒否状態を引き起こすことになります。OWASP Webテストガイドには、[XXEに関する次の例](https://goo.gl/QGQkEX "Testing for XML Injection (OTG-INPVAL-008)")が含まれています。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>
```

この例では、ローカルファイル`/dev/random`がバイトストリームが返されるところで開かれているため、サービス拒否攻撃を引き起こす可能性があります。

XMLはあまり一般的ではなくなっているので、アプリ開発における現在の傾向は主にREST/JSONベースのサービスに焦点を合わせています。ただし、XMLクエリーを作成するためにユーザー提供または信頼できないコンテンツが使用されることがまれにありますが、iOSのNSXMLParserなどのローカルXMLパーサーによって解釈される可能性があります。そのため、上記の入力は常に検証され、メタ文字はエスケープされるべきです。

#### Injection Attack Vectors

モバイルアプリへの攻撃面は、通常のWebおよびネットワークアプリケーションとはまったく異なります。モバイルアプリがネットワーク上のサービスを公開することはあまりありません。また、アプリのユーザーインターフェイスに実行可能な攻撃経路があることは稀です。アプリに対するインジェクション攻撃は、悪意のあるアプリがデバイス上で実行されている別のアプリを攻撃するプロセス間通信(IPC)インターフェイスを介して発生する可能性が最も高いです。

潜在的な脆弱性を見つけることは、次のいずれかから始まります。

 - 信頼できない入力値が利用可能なエントリポイントを特定し、それらの場所からトレースして、宛先に潜在的に脆弱な機能が含まれているかどうかを確認します。
 - 既知の危険なライブラリ/API呼び出(SQLクエリなど)を識別し、未チェックの入力値がそれぞれのクエリと正常に連携しているかどうかを確認します。

手動によるセキュリティレビューでは、両方のテクニックを組み合わせる必要があります。一般に、信頼できない入力値は次の経路を通じてモバイルアプリに挿入されます。

 - IPCコール
 - カスタムURLスキーム
 - QRコード
 - Bluetooth、NFC、またはその他の手段で受信した入力ファイル
 - ペーストボード
 - ユーザーインターフェース

次のベストプラクティスに従っているかを確認してください。

 - 信頼できない入力値は、許容される値をホワイトリストを用いて型チェックおよび/または値検証されている。
 - データベースクエリを実行するときには、変数バインディング付きのプリペアードステートメント(つまり、パラメータ化クエリ)が使用されている。プリペアードステートメントが定義されている場合、ユーザー提供のデータとSQLコードは自動的に分離されるようになっている。
 - XMLデータをパースする際は、XXE攻撃を防ぐために、パーサーアプリケーションが外部エンティティの解決を拒否するように設定されている。
 - x509フォーマットの証明書を扱うときは、安全なパーサーを必ず使用している。たとえば、バージョン1.6より下のBouncy Castleでは、安全でないリフレクションを使ってリモートでコードを実行することができます。

OS固有のテストガイドで、各モバイルOSの入力ソースと潜在的に脆弱なAPIに関する詳細を説明します。

### Memory Corruption Bugs

メモリ破壊バグはハッカーにとっての人気の主力です。このタイプのバグは、プログラムが意図しないメモリ位置にアクセスする原因となるプログラミングエラーから発生します。正しい条件下で、攻撃者はこの動作を利用して脆弱なプログラムの実行フローを乗っ取り、任意のコードを実行することができます。この種の脆弱性はさまざまな方法で発生します。

- バッファオーバーフロー: これは、特定の操作に対して割り当てられたメモリ範囲を超えてアプリが書き込みを行うプログラミングエラーを表します。攻撃者はこの欠陥を利用して、関数ポインタなど、隣接メモリにある重要な制御データを上書きすることができます。バッファオーバーフローは、以前は最も一般的な種類のメモリ破壊のバグでしたが、さまざまな要因により、あまり利用されなくなりました。特に、安全でないC言語のライブラリ関数を使用する際のリスクに対する開発者の意識は、現在では一般的なベストプラクティスで、バッファオーバーフローのバグを見つけることは比較的簡単です。しかし、それでもそのような欠陥についてテストする価値があります。

- 範囲外アクセス: バグのあるポインタ演算により、ポインタまたはインデックスが、意図したメモリ構造(バッファまたはリストなど)の範囲外の位置を参照することがあります。アプリが範囲外のアドレスに書き込もうとすると、クラッシュまたは意図しない動作が発生します。攻撃者がターゲットオフセットを制御し、ある程度書き込まれたコンテンツを操作できる場合、[コード実行の悪用が考えられます](https://www.zerodayinitiative.com/advisories/ZDI-17-110/)

- ダングリングポインタ: メモリ位置への着信参照を持つオブジェクトが削除または割り当て解除されたが、オブジェクトポインタがリセットされていない場合に発生します。プログラムが後で *dangling* ポインタを使用して、すでに割り当て解除されているオブジェクトの仮想関数を呼び出す場合、元のvtableポインタを上書きすることによって実行を乗っ取ることができます。あるいは、ダングリングポインタによって参照されるオブジェクト変数または他のメモリ構造を読み書きすることが可能です。

- 解放後使用: これは、解放された(割り振り解除された)メモリーを参照しているダングリング・ポインターの特別な場合を指します。メモリアドレスがクリアされると、その位置を参照しているすべてのポインタが無効になり、メモリマネージャはそのアドレスを使用可能なメモリのプールに返します。このメモリ位置が最終的に再割り当てされるとき、オリジナルのポインタにアクセスすることは新しく割り当てられたメモリに含まれるデータを読み書きするでしょう。これは通常データの破損や未定義の動作につながりますが、巧妙な攻撃者は適切なメモリ位置を設定して命令ポインタの制御を利用することができます。

- 整数オーバーフロー: 算術演算の結果がプログラマーによって定義された整数型の最大値を超えると、最大整数値を「折り返す」値になり、必然的に小さい値が格納されます。逆に、算術演算の結果が整数型の最小値よりも小さい場合、結果が予想よりも大きいところで *integer underflow* が発生します。特定の整数オーバーフロー/アンダーフローバグが悪用可能かどうかは、整数の使用方法によって異なります。たとえば、整数型がバッファの長さを表す場合、これによりバッファオーバーフローの脆弱性が生じる可能性があります。

- フォーマット文字列の脆弱性: チェックされていないユーザ入力値が C言語の関数の`printf()` ファミリに渡される場合、攻撃者はメモリにアクセスするために '％c'や '％n'などのフォーマットトークンを挿入する可能性があります。フォーマット文字列のバグは、その柔軟性のために悪用するのに便利です。プログラムが文字列フォーマット操作の結果を出力した場合、攻撃者は任意にメモリの読み書きを行うことができるため、ASLRなどの保護機能を回避することができます。

メモリ破壊を悪用する主な目的は、通常、攻撃者が *shellcode* と呼ばれる組み立てられた機械語命令を置いた場所にプログラムフローをリダイレクトすることです。iOSでは、データ実行防止機能(名前が示すとおり)によって、データセグメントとして定義されたメモリからの実行が防止されます。この保護を回避するために、攻撃者はリターン指向プログラミング(ROP)を利用します。このプロセスでは、これらのガジェットが攻撃者にとって有用な機能を実行する可能性があるテキストセグメント内の既存の小さいコードチャンク("ガジェット")を連鎖させるか、攻撃者が *シェルコード* を保存した場所のメモリ保護設定を変更します。

Androidアプリは、ほとんどの場合、設計上、メモリ破損の問題から本質的に安全なJavaで実装されています。 しかし、JNIライブラリを利用するネイティブアプリはこの種のバグの影響を受けやすいです。

#### Buffer and Integer Overflows

次のコードスニペットは、バッファオーバーフローの脆弱性を引き起こす条件の簡単な例を示しています。

```c
 void copyData(char *userId) {  
    char  smallBuffer[10]; // size of 10  
    strcpy(smallBuffer, userId);
 }  
```

潜在的なバッファオーバーフローを識別するために、安全でない文字列関数(`strcpy`、` strcat`、 その他 "str" 接頭辞で始まる関数など)の使用や、サイズ制限されたバッファへのユーザ入力値のコピーなど、潜在的に脆弱なプログラミング構造を探します。以下は安全でない文字列関数を利用しており、危険と判断されるものです。

    - `strcat`
    - `strcpy`
    - `strncat`
    - `strlcat`
    - `strncpy`
    - `strlcpy`
    - `sprintf`
    - `snprintf`
    - `gets`

また、"for"または"while"ループとして実装されているコピー操作のインスタンスを探し、長さのチェックが正しく実行されていることを確認します。

次のベストプラクティスに従っていることを確認してください。

- 配列の索引付け、バッファー長の計算、またはその他のセキュリティー上重要な操作に整数変数を使用する場合は、符号なし整数型が使用されていることを確認し、整数ラップの可能性を防ぐための前提条件テストを実行している。
- アプリは `strcpy`のような安全でない文字列関数、`str`プレフィックスで始まる他のほとんどの関数、 `sprint`、` vsprintf`、 `gets`などを使用していない。
- アプリにC++コードが含まれている場合は、ANSI C++文字列クラスが使用されている。
- Objective-Cで書かれたiOSアプリはNSStringクラスを使用している。iOS上のCアプリケーションは、Core Foundationの文字列表現であるCFStringを使用する必要があります。
- 信頼できないデータはフォーマット文字列に連結されない。

#### Static Analysis

低レベルの静的コード分析は、それだけで簡単に本が書けるくらい複雑なトピックです。[RATS](https://code.google.com/archive/p/rough-auditing-tool-for-security/downloads "RATS - Rough auditing tool for security")のような自動化された道具と限られた手作業による検査努力との組み合わせは、通常、ぶら下がっている果物を識別するのに十分です。ただし、メモリ破損は多くの場合複雑な原因から生じます。たとえば、解放後使用のバグは、実際にはすぐには明らかにならず、複雑で直感に反する競合状態の結果である可能性があります。見過ごされがちなコードの欠陥の深い例から現れるバグは一般的に動的分析を通して、またはプログラムの深い理解を得るために時間を費やすテスターによって発見されます。

#### Dynamic Analysis

メモリ破損のバグは、入力ファジングによって最もよく発見されます。すなわち潜在的な脆弱性の状態を調査するために不正な形式のデータが継続的にアプリに送信される自動ブラックボックスソフトウェアテスト手法によって。このプロセス中に、アプリケーションの誤動作やクラッシュが監視されます。クラッシュが発生した場合、(少なくともセキュリティテスターにとって)希望は、クラッシュを引き起こす条件を解析することで悪用可能なセキュリティ上の欠陥が明らかになることです。

ファズテストのテクニックやスクリプト("fuzzers"と呼ばれることが多い)は、通常、semi-correctな方法で構造化された入力値の複数のインスタンスを生成します。基本的に、生成された値または引数はターゲットアプリケーションによって少なくとも部分的に受け入れられますが、無効な要素も含み、入力処理の欠陥や予期しないプログラムの動作を引き起こす可能性があります。優れたfuzzerはかなりの量の可能なプログラム実行経路(すなわち、高カバレッジ出力)を明らかにします。入力値は、最初から生成される("世代別)か、既知の有効な入力データを変更したものから派生します("変更ベース")。

ファジングの詳細については、[OWASP Fuzzing Guide](https://www.owasp.org/index.php/Fuzzing "OWASP Fuzzing Guide")を参照してください。

### Cross-Site Scripting Flaws

クロスサイトスクリプティング(XSS)の問題があると、攻撃者はユーザーが閲覧したWebページにクライアントサイドのスクリプトを挿入することができます。この種の脆弱性はWebアプリケーションでは一般的なものになります。ユーザーがブラウザで挿入されたスクリプトを閲覧すると、攻撃者は同じオリジンポリシーを迂回し、さまざまな不正利用(例えば、セッションクッキーの盗用、キー押下の記録、任意の操作の実行など)を可能にします。

*ネイティブアプリ* のコンテキストでは、XSSのリスクは、これらの種類のアプリケーションがWebブラウザに依存しないという単純な理由ではるかに低くあります。ただし、iOSの"UIWebView"やAndroidの"WebView"などのWebViewコンポーネントを使用するアプリは、このような攻撃に対して潜在的に脆弱です。

より古く、よく知られている例は[local XSS issue in the Skype app for iOS, first identified by Phil Purviance]( https://superevr.com/blog/2011/xss-in-skype-for-ios)になります。Skypeアプリはメッセージ送信者の名前を正しくエンコードできなかったため、攻撃者が悪意のあるJavaScriptを挿入してユーザーがメッセージを表示したときに実行される可能性があります。彼の概念実証では、Philはこの問題を悪用してユーザーのアドレス帳を盗む方法を示しました。

#### Static Analysis

現在表示されているWebViewを詳しく調べて、アプリによってレンダリングされた信頼できない入力値について調べます。

WebViewによって開かれたURLがユーザの入力値によって部分的に決定されている場合、XSSの問題が存在する可能性があります。次の例は、[Linus Särudによって報告されたZoho Web Service](https://labs.detectify.com/2015/02/20/finding-an-xss-in-an-html-based-android-application/)のXSSに関するものになります。


```java
webView.loadUrl("javascript:initialize(" + myNumber + ");");
```

ユーザーの入力値によって決定されたXSSの別の例は、パブリックオーバーライドメソッドです。

Java

```java
@Override
public boolean shouldOverrideUrlLoading(WebView view, String url) {
  if (url.substring(0,6).equalsIgnoreCase("yourscheme:")) {
    // parse the URL object and execute functions
  }
}
```
Kotlin

```kotlin
    fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
        if (url.substring(0, 6).equals("yourscheme:", ignoreCase = true)) {
            // parse the URL object and execute functions
        }
    }
```

Sergey Bobrovは次の[HackerOne report](https://hackerone.com/reports/189793)でこれを利用することができました。htmlパラメータへの入力値はすべてQuoraのActionBarContentActivityで信頼されます。ペイロードは、adb、ModalContentActivityを介したクリップボードデータおよびサードパーティ製アプリケーションのIntentsを使用して成功しました。

- ADB
```shell
adb shell
am start -n com.quora.android/com.quora.android.ActionBarContentActivity -e url 'http://test/test' -e html 'XSS<script>alert(123)</script>'
```
- Clipboard Data
```shell
am start -n com.quora.android/com.quora.android.ModalContentActivity -e url 'http://test/test' -e html '<script>alert(QuoraAndroid.getClipboardData());</script>'
```
- 3rd party Intent
```java
Intent i = new Intent();
i.setComponent(new ComponentName("com.quora.android","com.quora.android.ActionBarContentActivity"));
i.putExtra("url","http://test/test");
i.putExtra("html","XSS PoC <script>alert(123)</script>");
startActivity(i);
```

WebViewを使用してリモートWebサイトを表示している場合、HTMLをエスケープする負担はサーバー側に移ります。WebサーバにXSSの欠陥がある場合、これをWebViewのコンテキストでスクリプトを実行するのに使用することができます。そのため、Webアプリケーションのソースコードの静的分析を実行することが重要です。

次のベストプラクティスに従っていることを確認してください。

- 信頼できないデータは、絶対に必要でない限り、HTML、JavaScript、または他の解釈されたコンテキストでは表示されない。

- HTMLエンティティエンコーディングなど、エスケープ文字に適切なエンコーディングが適用されている。注: HTMLが他のコード内にネストされている場合(例えば、JavaScriptブロック内にあるURLをレンダリングする場合)、エスケープ規則は複雑になります。

レスポンスでデータがどのようにレンダリングされるかを検討してください。たとえば、データがHTMLコンテキストでレンダリングされる場合、エスケープする必要がある6つの制御文字がどうなるか。

| Character  | Escaped      |
| :-------------: |:-------------:|
| & | &amp;amp;|
| < | &amp;lt; |
| > | &amp;gt;|
| " | &amp;quot;|
| ' | &amp;#x27;|
| / | &amp;#x2F;|

エスケープルールおよびその他の防止策の包括的なリストについては、[OWASP XSS Prevention Cheat Sheet](https://goo.gl/motVKX "OWASP XSS Prevention Cheat Sheet")を参照してください。

#### Dynamic Analysis

XSSは、手動および/または自動入力ファジング、つまりWebアプリケーションが無効な入力を拒否するか、その出力でHTMLメタ文字をエスケープすることを確認するために使用可能なすべての入力フィールドに特殊文字を挿入することでよく検出できます。

[reflected XSS attack](https://goo.gl/eqqiHV "Testing for Reflected Cross site scripting (OTG-INPVAL-001)") とは、悪意のあるコードが悪意のあるリンクを介して挿入されるエクスプロイトを指します。これらの攻撃をテストするには、自動入力ファジングが効果的な方法と考えられています。たとえば、[BURP Scanner](https://portswigger.net/burp/ "Burp Suite")は、反映されたXSSの脆弱性を識別するのに非常に効果的です。自動分析と同様に、すべての入力ベクトルがテストパラメータの手動レビューで網羅されていることを確認してください。

### References

#### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

#### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

#### CWE

- CWE-20 - Improper Input Validation

#### XSS via start ContentActivity

- https://hackerone.com/reports/189793

#### Android, SQL and ContentProviders or Why SQL injections aren't dead yet ?

- http://blog.ostorlab.co/2016/03/android-sql-and-contentproviders-or-why.html
