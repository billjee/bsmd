import asyncio
from os import environ
from pathlib import Path
from tempfile import gettempdir

PROTOCOL_VERSION = 2


def path_home() -> Path:
    return Path.home().joinpath(".indy_client")


def get_pool_genesis_txn_path(pool_name):
    path_temp = Path(gettempdir()).joinpath("indy")
    path = path_temp.joinpath("{}.txn".format(pool_name))
    save_pool_genesis_txn_file(path)
    return path



def pool_genesis_txn_data():
    pool_ip = environ.get("TEST_POOL_IP", "127.0.0.1")
    return "\n".join([
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node1","blskey":"4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba","blskey_pop":"RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1","client_ip":"18.218.86.252","client_port":9702,"node_ip":"18.218.86.252","node_port":9701,"services":["VALIDATOR"]}},"dest":"Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv"}},"metadata":{{"from":"Th7MpTaRZVRYnPiabds81Y"}},"type":"0"}},"txnMetadata":{{"seqNo":1,"txnId":"fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node2","blskey":"37rAPpXVoxzKhz7d9gkUe52XuXryuLXoM6P6LbWDB7LSbG62Lsb33sfG7zqS8TK1MXwuCHj1FKNzVpsnafmqLG1vXN88rt38mNFs9TENzm4QHdBzsvCuoBnPH7rpYYDo9DZNJePaDvRvqJKByCabubJz3XXKbEeshzpz4Ma5QYpJqjk","blskey_pop":"Qr658mWZ2YC8JXGXwMDQTzuZCWF7NK9EwxphGmcBvCh6ybUuLxbG65nsX4JvD4SPNtkJ2w9ug1yLTj6fgmuDg41TgECXjLCij3RMsV8CwewBVgVN67wsA45DFWvqvLtu4rjNnE9JbdFTc1Z4WCPA3Xan44K1HoHAq9EVeaRYs8zoF5","client_ip":"13.58.138.233","client_port":9704,"node_ip":"13.58.138.233","node_port":9703,"services":["VALIDATOR"]}},"dest":"8ECVSk179mjsjKRLWiQtssMLgp6EPhWXtaYyStWPSGAb"}},"metadata":{{"from":"EbP4aYNeTHL6q385GuVpRV"}},"type":"0"}},"txnMetadata":{{"seqNo":2,"txnId":"1ac8aece2a18ced660fef8694b61aac3af08ba875ce3026a160acbc3a3af35fc"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node3","blskey":"3WFpdbg7C5cnLYZwFZevJqhubkFALBfCBBok15GdrKMUhUjGsk3jV6QKj6MZgEubF7oqCafxNdkm7eswgA4sdKTRc82tLGzZBd6vNqU8dupzup6uYUf32KTHTPQbuUM8Yk4QFXjEf2Usu2TJcNkdgpyeUSX42u5LqdDDpNSWUK5deC5","blskey_pop":"QwDeb2CkNSx6r8QC8vGQK3GRv7Yndn84TGNijX8YXHPiagXajyfTjoR87rXUu4G4QLk2cF8NNyqWiYMus1623dELWwx57rLCFqGh7N4ZRbGDRP4fnVcaKg1BcUxQ866Ven4gw8y4N56S5HzxXNBZtLYmhGHvDtk6PFkFwCvxYrNYjh","client_ip":"3.17.40.8","client_port":9706,"node_ip":"3.17.40.8","node_port":9705,"services":["VALIDATOR"]}},"dest":"DKVxG2fXXTU8yT5N7hGEbXB3dfdAnYv1JczDUHpmDxya"}},"metadata":{{"from":"4cU41vWW82ArfxJxHkzXPG"}},"type":"0"}},"txnMetadata":{{"seqNo":3,"txnId":"7e9f355dffa78ed24668f0e0e369fd8c224076571c51e2ea8be5f26479edebe4"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node4","blskey":"2zN3bHM1m4rLz54MJHYSwvqzPchYp8jkHswveCLAEJVcX6Mm1wHQD1SkPYMzUDTZvWvhuE6VNAkK3KxVeEmsanSmvjVkReDeBEMxeDaayjcZjFGPydyey1qxBHmTvAnBKoPydvuTAqx5f7YNNRAdeLmUi99gERUU7TD8KfAa6MpQ9bw","blskey_pop":"RPLagxaR5xdimFzwmzYnz4ZhWtYQEj8iR5ZU53T2gitPCyCHQneUn2Huc4oeLd2B2HzkGnjAff4hWTJT6C7qHYB1Mv2wU5iHHGFWkhnTX9WsEAbunJCV2qcaXScKj4tTfvdDKfLiVuU2av6hbsMztirRze7LvYBkRHV3tGwyCptsrP","client_ip":"3.17.121.212","client_port":9708,"node_ip":"3.17.121.212","node_port":9707,"services":["VALIDATOR"]}},"dest":"4PS3EDQ3dW1tci1Bp6543CfuuebjFrg36kLAUcskGfaA"}},"metadata":{{"from":"TWwCRQRZ2ZHMJFn9TzLp7W"}},"type":"0"}},"txnMetadata":{{"seqNo":4,"txnId":"aa5e817d7cc626170eca175822029339a444eb0ee8f0bd20d3b0b76e566fb008"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node5","blskey":"2JSLkTGhnG3ZzGoeuZufc7V1kF5wxHqTuSUbaudhwRJzsGZupNHs5igohLnsdcYG7kFj1JGC5aV2JuiJtDtHPKBeGw24ZmBJ44YYaqfCMi5ywNyP42aSjMkvjtHrGS7oVoFbP4aG4aRaKZL3UZbbGcnGTK5kfacmBNKdPSQDyXGCoxB","blskey_pop":"QkfRaLjoiQRyY5bmsJYRiDSvUrkVTHr671vTodMKTKTfKeVuawPLhGXk2few4bo5ZMC1LFMfHhaiMfJYPTzzJbdnWuZeucWcZjgcjAcBfg5GXSNUp2swExjju359MJLb1zQMoo2yFH3VCCkgtohHA1y5AbxAmzer4Rai2ndVHtyKoV","client_ip":"18.219.203.174","client_port":9710,"node_ip":"18.219.203.174","node_port":9709,"services":["VALIDATOR"]}},"dest":"4SWokCJWJc69Tn74VvLS6t2G2ucvXqM9FDMsWJjmsUxe"}},"metadata":{{"from":"92PMXtzRGuTAhAK5xPbwqq"}},"type":"0"}},"txnMetadata":{{"seqNo":5,"txnId":"5abef8bc27d85d53753c5b6ed0cd2e197998c21513a379bfcf44d9c7a73c3a7e"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node6","blskey":"3D5JAwAhjW5gik1ogKrnQaVrHY94e8E56iA5UifXjjYypMm2LifLiaRtgWJPiFA6uv2EiGy4MYByZ88Rmi8K3mUvb9TZeR9sdLBxsTdqrikeenac8ZVNkdCaFmGWcw8xVGqgv9cs574YDj7nuLHbJUDXN17J2fzQiD83iVQVQHW1RuU","blskey_pop":"RAMb2cWGE5K4VdTowDSCnTMi7bbHfLbELBL1XGWMSDgE5DMqGFgASmrrZnpqtyz9trDaf3VcE6LjyT72bHxR8ecPonBNUcuu5j3887C4RtVxPEkNjft2yZ2pMyYCXRiJ4bRmJMSvQa28xjXrTJ3wypzoeoa5DFA9Y6X8TLUe7hQLpP","client_ip":"13.58.142.30","client_port":9712,"node_ip":"13.58.142.30","node_port":9711,"services":["VALIDATOR"]}},"dest":"Cv1Ehj43DDM5ttNBmC6VPpEfwXWwfGktHwjDJsTV5Fz8"}},"metadata":{{"from":"HaN1iLFgVfM31ssY4obfYN"}},"type":"0"}},"txnMetadata":{{"seqNo":6,"txnId":"a23059dc16aaf4513f97ca91f272235e809f8bda8c40f6688b88615a2c318ff8"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node7","blskey":"4ahBpE7gVEhW2evVgS69EJeSyciwbbby67iQj4htsgdtCxxXsEHMS6oKVeEQvrBBgncHfAddQyTt7ZF1PcfMX1Gu3xsgnzBDcLzPBz6ZdoXwi3uDPEoDZHXeDp1AFj8cidhfBWzY1FfKZMvh1HYQX8zZWMw579pYs3SyNoWLNdsNd8Q","blskey_pop":"RSZqkPwZKyXxn4qwDNQ9m9hkqBbpdMCzz9pTobyxArnQbZiLkxFTStdGyDmwmyH7fRkXygyTp7ib4VJWeJitfDbZyv2yTr3ShbBWvYEkX7jGUZDdoS3EXYfAserSLsPEdL1U3Y9tuXRuEKd99VHhcem1sPop5mNn92ryKZGvv1auWP","client_ip":"52.14.133.91","client_port":9714,"node_ip":"52.14.133.91","node_port":9713,"services":["VALIDATOR"]}},"dest":"BM8dTooz5uykCbYSAAFwKNkYfT4koomBHsSWHTDtkjhW"}},"metadata":{{"from":"BgJMUfWjWZBDAsu251dtrF"}},"type":"0"}},"txnMetadata":{{"seqNo":7,"txnId":"e5f11aa7ec7091ca6c31a826eec885da7fcaa47611d03fdc3562b48247f179cf"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node8","blskey":"zUoh7Cyeq4cFGeLXjQswFkH25JcyUZKG39t6wRf25A53yBETgf2N5c3z1PBv2XpjExio6s9sEAgfa2cZE6WemYWUjXTvgqmzcQt8JUt9EigzNedxNDjY6JuxnyThfH48n4i1SWrDtEsQJHYXVV3NDPwVNYYYDdFMKZsmNF9BWMc94g","blskey_pop":"RTkcgTwyvdntnssL161kxiSxtu4WKkkKAJDPKLN9HrPjm5sGRAnZ1Xu3km2HhxhS4GK7VmqMF1AFCSi82DRMX1BxgpYxTiax6R7a18E4Rup4dBNPGtP5GS9bMz6KZgr3m1WYJPiyW2cBZ29uDbnA9PPu4QbJQCTDWCiYAqMYgeECqV","client_ip":"52.14.39.119","client_port":9716,"node_ip":"52.14.39.119","node_port":9715,"services":["VALIDATOR"]}},"dest":"98VysG35LxrutKTNXvhaztPFHnx5u9kHtT7PnUGqDa8x"}},"metadata":{{"from":"KUQp6Kpd5nZ2HocYj3VqVY"}},"type":"0"}},"txnMetadata":{{"seqNo":8,"txnId":"2b01e69f89514be94ebf24bfa270abbe1c5abc72415801da3f0d58e71aaa33a2"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node9","blskey":"2VRLhcfMpdMm2BudHkJQwfouX8zsjYjuHYNt72Qba5NANN8Yeb1kZGpgh8de7sW1nSof6EQzJihumkjzdEdzi2LYdN8Xx4JQ2Yk6sy3oMvvaRFFHxNNh9U3AzyJhSrA9JJEmjEP5RNRvULbquVo6Bfb7T1hwdBfaoiVixvtLP7CqDd1","blskey_pop":"QpxAXPQc9cCV5LNhhRBq3BtHTtbHhoHSfaHTtgssa6dTuHMLxnM1Wn4C3jyW1F5uEhhsxw4RB3ajtAaXEYZHThtxaXFLBDN7LfQXwxsW6kXTgZVXzU353AYViW4g5hyteW9oXhBa4kn2sxX3tenEQUVLeWg7bwPjGQ7CLSDsaxytaB","client_ip":"18.219.90.32","client_port":9718,"node_ip":"18.219.90.32","node_port":9717,"services":["VALIDATOR"]}},"dest":"6pfbFuX5tx7u3XKz8MNK4BJiHxvEcnGRBs1AQyNaiEQL"}},"metadata":{{"from":"FiYoKcGabuCtTN8fi9J8JD"}},"type":"0"}},"txnMetadata":{{"seqNo":9,"txnId":"93a39f3b502aeb67112cfa94fd7deb372bf41d20e4e8fea7c330879e1d920071"}},"ver":"1"}}'.format(
            pool_ip, pool_ip),
        '{{"reqSignature":{{}},"txn":{{"data":{{"data":{{"alias":"Node10","blskey":"2oos5c9W8KB524HLcUKusmuVH2bdqwEuapnw1YkPn74HXJQRu8ZSfAkMpfJnqH9ijWTHJu21Qeu6Sh9cCMCqhtdgijvQFxATY48cbxkBiw3d884oujjfezJ8ik1T3oHAGxdoQYCzkCAWYiuGHFJZRzK7zbQMx3LW4cD3iWAXAawaRyk","blskey_pop":"Qs2Sw26PMtmGJf6gfP88Q3KTiCcaZptvPLJ6kKbMjMnxP5UvPQxpTySTuzPT5j9eARuKTYueMffz8xtnurdfqJMxHzbCQZw8UF2BeLnpE7JkAWgSxjBbiH9KNmu3U7Zcq3braa3rpw5F8yF11mqLVSUBaNX2UvFXC2kVvDCZcLMmKD","client_ip":"18.191.198.202","client_port":9720,"node_ip":"18.191.198.202","node_port":9719,"services":["VALIDATOR"]}},"dest":"HaNW78ayPK4b8vTggD4smURBZw7icxJpjZvCMLdUueiN"}},"metadata":{{"from":"CrqD2jmZ5jSboqBw9PuoH5"}},"type":"0"}},"txnMetadata":{{"seqNo":10,"txnId":"4309b76efa25582ebc812ab702fee25c5ec2768e601156a9323d0bda352ed574"}},"ver":"1"}}'.format(
            pool_ip, pool_ip)
    ])


def save_pool_genesis_txn_file(path):
    data = pool_genesis_txn_data()

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(str(path), "w+") as f:
        f.writelines(data)


def run_coroutine(coroutine, loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(coroutine())






