## json

    x encode()
    - requests.read() return str in Ubuntu ?

## serial_num:

    o 20 octet 0-9

## not after:

    o 2 weeks

## not before:

    o skew option
    o default 30 minute

## retry interval:

    o client
    o proxy
    o ca

## version:

    o 3 じゃなくて 2

## ID

    x clientはSANには入れない。
    x session nameはいらない。
    o clientはSANに入れる。LAN内で使うため。
    o clientはsession nameをCNに入れる。
    o RAが外のアドレス(WAN-IP)をCAに伝える。
    - CA-RAの相互認証
    o CAはWAN-IPをSANに追加する。
    x access urlを CNに入れる。
    o access name + fqdn を SAN にいれる。

## constraints:

    o CA: true の行が入らない
    - extendedkeyusage, keyusage: 後から考える
    o subjectkeyindentifier, flase, "hash")

## demo

    - dhcp からのアドレス
