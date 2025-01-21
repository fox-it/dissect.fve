from __future__ import annotations

import hashlib

import pytest

from dissect.fve.crypto import create_cipher, elephant, parse_cipher_spec


@pytest.mark.parametrize(
    ("cipher_spec", "key", "buf", "sector", "expected"),
    [
        (
            "aes-ecb",
            "f76644d736c85de61d1996523382fb0294c06558a484a306ef5c06aa994a0919",
            (
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
                "46a8f2cfca6410fa89bbbce18987bdd546a8f2cfca6410fa89bbbce18987bdd5"
            ),
            1,
            "6caf38d537984e261527b8caef5f990fb91415a1db917198821a79ed28997973",
        ),
        (
            "aes-cbc-128-eboiv",
            "84c3a3157e5f21dee140005220bc940e",
            (
                "30d6c53b40e537d33972ed6ac97292f1308fbc15f77599b5dfd5a58fa52df42d"
                "24a187bec736d8818fd4a0f0f6f68a2f6070a1045fb32da7d13ee4d06fb8d2bd"
                "206c593497936224ea06960aadd0f8442926ed799d7bfef791037903239c11a5"
                "1a090e72146eb551cf3c65d3aa3311f1016471339f3fb38c0e3b74ba489c44ad"
                "efb454abfa777e8a4ab4cc11361d197717748fb3d53d5cccc3c873be4d90a656"
                "32d4503f87160ea0763652438c03d3523b574fc2a9579b4fdc137352a8351add"
                "6f21d9ec4e9dcb16404845556d44ce10358f62112ff44d171ea2078824354690"
                "f36e7f3751e618b6f2125f85d89aff9e554dd7c3f4a10a0fbc8a691b5a106759"
                "0de812794752021abf8bf022ef9316fd30df475074610a3e73cbd4537e785bff"
                "16b19746550285df4201fb018a7ad2c1d3c0be0bd03c2e28b33c7cbe5a304ae1"
                "00fe35d02f53e7cbf724c3d6654942c7f87cd29ce94c7b7513d77ba1e6cd6587"
                "668ab9242b30a2d3fa194c59e737f8c0c47f0a58c120457574b31b2d5628e3a4"
                "95c47d00f456af86e2909b10386d9755e08f8dd45a3b442166d10b938b6c4e06"
                "d934230f5957ae1a78dfd9f54425f079fb0b19f10dc13ba8f8957e05d72ca459"
                "83fd58f7c68e2f338e64a53d967ddd68cb4eb36837f447005ace7064af086abd"
                "e518cdc3c3651da1eb7d723b35c60a72f02cb15b6113206c7fef62a28d8b6302"
            ),
            69632,
            "330ae9824fdd919fbe5c0eb7f48c9f9df2a002557eb5daa2f8be93d25f4dccc5",
        ),
        (
            "aes-cbc-256-eboiv",
            "dd3885ef9948c8dc6ad1b54a6c4a4b6fb74b44d1d9775ac7ed186c35f1b59022",
            (
                "7018bff0f32d94d4463a0c0ef56825538d2f98f4be7230f240b861678da36e0c"
                "30b1a2d71f7d3d3e6e3fc13cb3ec0e9fef09ac344e0c57c9d4aa72c1e7ccb266"
                "fb5b9bdacb5f5ddd3db573593e045ec1efb2702831098f30f2d88ab6c6bb03ac"
                "af0ada116ea4fe8acb5df6f1c48daabac5d6ac89333e15205dd0e55ba0fb9451"
                "89635b16549ee2b8777e7de971dea1a779d9ecbb973b1697af8619c9924874f9"
                "86aaebbaa41dec271809f344ac45f0a4d8aef2d22619bbd52cc91e2e3ff66577"
                "798a979aa6397ce22f2bbbaed4e57ff0dd202f6273183a454db9d16a87531320"
                "c1632fda49a1265929df4d6ece0c385330162cd211677f168e969e913cae39b9"
                "70e16e3b2166b6c3f69f73e04451468d72781aa09002eca7734faa04f11377f9"
                "552e057fc8dd6b750ab507737bee6235517075588bb67dd1e2ad792bcfd79b91"
                "9edf36e6ecef33cd4e654252495d766c47514694cacf1e298a66ac24bbbbd851"
                "7bf4874f587b7a6229d01099c9b6b50d29b1d8746a68b8c5c3bcf9f4b4591298"
                "5feb89e8f28ccb8b2fab1e6038a3ea25b76fdb047b5e08216464871d9e9c51a2"
                "4dc634466a8cbb8babd4e150ff3243df5a12b17af5128078a9a03f8601029037"
                "cccc89c70e13c93ec29fa6435b23d75452623a709b3c207a84769d5dea5f3d5c"
                "f130170ec80bbaf7717324a87af1e81a7a1d915b35fd3d019aa6b51357dded85"
            ),
            69632,
            "1c9af69f51facaf1588143be07b2bffe0bfd4be0036b3d569e13f68020a7e469",
        ),
        (
            "aes-cbc-128-elephant",
            (
                "10730f695df62a49cd3aa1b1c9ae3edf2229c338a3740830e2b19d2b83f9cada"
                "268af0e0613921085edc89e1b804de354fd265acf4e5c410b47764bb9565666b"
            ),
            (
                "2895d4deed18488410dc2cd5db6bbf422fa34ac01a2a1322cdcf62ee0767c3b2"
                "d4288ed284b4f819d2a1c37618fc9a1408932d8400bda39aaba2d611399220b1"
                "6fa0bc2f791b87ab4adbd5cf6e6fcf1821f62fafb33750b2056da73d35356ac0"
                "eee55bda92582720474bbaac2ff360d4fa168c49984d306ee73bc074a1978b97"
                "f09f37d5aeb81d9452b5d04326b490e4e7e3c362cbad3467fe9a9cb6a2d67cf1"
                "17c4d482bfc9abeb6b68f694a55c11ccb33bf879ba5e318f4b0f7433d0971a0a"
                "18533531d818eb0b5980596d98e07bf82bb126ac531a738013eb7b00a1ab8306"
                "6177afd93617c5b31378990e47004974343bd76cdac9e56e6e05a4f831b2655e"
                "8263042dbbcc13b4b44f35a862f46f72816c76a36a684399b3ed76a53cdf225b"
                "c9693a8de876c871c9479b2cd519838ab2fafe27c9503e154745a3473e3d4ce5"
                "c958203cb27bfb24f7da9765ff922a885897bc0835d52e7ee4ff044a47ced516"
                "5537ac88f10c5d59f905ea4ffb6ff424ca2e578520c59042a774830063527d75"
                "2d5f8272b08160b2e184928876c7befbd9ca9d4c674b90c1b19ea23d01271d3c"
                "62f5aac812af0dd44c30c7bda69bd45c01b68f677c6ee416417e5437e799c776"
                "b264998dbeb65713269789c7443ae7f57c826eaa6a60116fb0b2950dff4ffc05"
                "1282fa9ae6f4c20ce1738ea898f70cd48dbf9e9325673b250e2deaa50408fb47"
            ),
            85072,
            "d94ac3b56f5307afa9350882f9b5d84401d1eac2dc0a27300376c2e5c80172d8",
        ),
        (
            "aes-cbc-256-elephant",
            (
                "3a600625f8fd5cc506cf8b30c8ca0600cc32f0c6b54c140789f7518c4fb5c71b"
                "a272f34f1a920d5be247298b5d233ce6199023c24d0aefec28717232f9894d1f"
            ),
            (
                "8568f934436237a034086e7acbb9b32f278c7fd1f9803d1d8d08000e8c9b6398"
                "0f9b72261175c71ec4b8f5a9e99830334a96460250d4a3030e2866341ac65e33"
                "39307198fcb64ed438592804148b917c5cfc2d0bb00c99f89568d68f914321d5"
                "4f8b70f6d7835f9b287f43b1ab99c5cadae38de1fb27f389a2ae22930aeb2269"
                "0ca3e176af6b1adfdee1d82229768179bec35729125287a2ab20be958c468a1d"
                "973e7b157d6562444dd4d7ae2ba21094597d98b8665af025e859dc7568a6cef4"
                "f615e02516eac6d4e82479a51548220707ba6a9fe13edf4797b1986085884f52"
                "b50f55bbb41f351ba87e388bbb11406a19e4c3fac1407d727c7aa95d41b40b1e"
                "bb996cecc7f329faad33af6c5f3e98e18078ab1242a2bc0e9ed90835e75730c9"
                "3697d57bf1c68204238ff099050108f1f6ec3fec06ff8f239b5089409a3ca10e"
                "8aa37180b62049cd5ce586e57f7c02afcf10f3ddd8328e9810a0c29df3d983b3"
                "dbef7cde8cfbc9f0f3f2aece11b332b8593bf94e66af9b3b44f01f056d4c462d"
                "868123c2b88dcd3fba831f9b9240ab0f985d1cf42d97504d535fa44edd6c371b"
                "5e56daadfbc2ba27db9ca65045d1eae97bc4f131f51a67baab3344c4af9eeab3"
                "f784b6f0bf1456d9bb0c0863ce7d6f8305ba2cc908fbef535d6a716cc583e934"
                "8d07ab73a517e015d52a2d9c496f8776b259995c3851e27c9776a2aa5b6520cb"
            ),
            85072,
            "d62b8dfa4eb68d5507bc446cb34cd1d5bc1a2425c2dd609c9920c5ec9d87308d",
        ),
        (
            "aes-xts-128-plain64",
            "4eb949c473f0edfc379ad041670ddb9c4da0abdb4482a2c8bb47250493aa1ed5",
            (
                "138bae29d1e47e38411a65675406cb9bc18f5eae362c3cdb6b58b9b39bad18d6"
                "cd4e3aad995f5681e0949914355e200701bf3d9ad8de9b8ed245be2b7c364b7c"
                "37c918181c25ea64fa88f8bb048a87122ea028c82fa05c18caa979d33b86808c"
                "18d6791c25eec448960aa4f98a666176a1b1eb50d8a0b96be740b51117b8f278"
                "18f5bf5afa794f2908b942bf3eb9725336db7c089a350186ef76c8e6035ca2b7"
                "257fb006776990b2304d0c98d6a923d170b621b343dc8be02d71cc4d18706e0e"
                "358e745cb0700f4f8250b3f3ebbe5889ed89d804051933e60c80c8ce038b6090"
                "5f3f6d23228b91162885dd8bcce2ff3e6f498acf2f4f349be7c931f4e4a1d9f5"
                "4e34a5754057df547377418f9e002c30e1e77ed623eddb11a1b7448569af9866"
                "34a12e8e71ddddd7395f3d9de5c7e9019eafc864914750f909b5298e14029b51"
                "9f4ee34c60be2f45d0b600e1e2f29e9c05c4c0a7ef6be1e82922d699dfcc61e8"
                "285850b080e4b9a151abc996a2571a689e9bb2ea53995e4c3191c81f50f8463b"
                "6f9e28f6cdd671c220472e0e5a5c4026baaed99c4bb170a2a9708d9974dba25e"
                "c102b881307dfa13c7a774243e66b499386523b426a575961444b91f85d7ab60"
                "b860a56fbe2c799fc4e29af79c27d2010431caa414fbb3acd3bae79f076f0974"
                "f548dd52f3273081b2a17695a0d4f365a4988ed5dc0bcc5503f63bc86ed613c5"
            ),
            69632,
            "01a264035f380f8edef7f377747cd4dbacff4be8fee23d6e9b8021766c9a3c0f",
        ),
        (
            "aes-xts-256-plain64",
            (
                "c74002df41f5eadeee2549fc009233a2a510726ce08736aba2f84a52ac6e7bbc"
                "56b8a824a4dc26cf9c4c2926386319d17427998e045ebfdc789e328e0dc97da4"
            ),
            (
                "d14389175de9e1ad3b7d9bd4605e16880489ad8ee851bad735c35acef1bc8f3a"
                "ff2ec2ee373a77c20fb471e7c9c177f213823629fbec4a369bf3aa58cf510a9f"
                "b7a36b9121894c502b6d5d12b5467e4babcb50fc852f03f01e419d96645f6763"
                "ad008285a35764fe2efba129bc217ab65a8890be355f33f9ff3d5d86cba22574"
                "369cace995fc792cb0186e84f9a138f65b57a28358d6a29a3b0e1a08451c1b4b"
                "8d2d1526dc986a6a509ca2d37ac971bfd11e0ca8f9098a3d16c46649d0bd6cc7"
                "10f44960a290b3f1d6380dfa03167c7035e10537158be830ae7ea3d2c01ff0fd"
                "6da772ca4d152dcdc12fdccc1b7cfc8578f4b052b6e7661717d8d374bc9f0bec"
                "cc9b04c3c30ce7acd30919f354b7549f2c023608d3d8c5519abb3e90d4c3ad35"
                "f25c7185ca4a5a4becffebcf8959349dca6c63cfc3ee6c195d92516fa68f5a27"
                "68b63b7e10bba4e97f9252a2cdc1ba7765ba01e6351afb82c6cfff3abc9e84f9"
                "5ca5a59d477d2b8bc90eacd4f3efc483068c52e340c88651d623178835aa084a"
                "095ef3e0c45b2752594693ffc7b63b2fe85182fa674672ec22bff855b3e6e13d"
                "c2af8ee44edde26c497be718bb51bd99e9188a3f071d10e2ba30a6f84dbfbf33"
                "14e8b5a670a8c96f3eb7efb35cc26e3fdd7b669e216f4b55dc4cb5d8f197069b"
                "d1ff2e796de40b3a5b04f3674a03a66e9065c1e8f3586d329623cc35e6a2b024"
            ),
            69632,
            "7d456ac1e51d71caa82560bbe343985120f82f4fce2c397e860af946be4471a7",
        ),
    ],
)
def test_crypto_ciphers(cipher_spec: str, key: str, buf: str, sector: int, expected: str) -> None:
    cipher = create_cipher(cipher_spec, bytes.fromhex(key))

    buf = bytes.fromhex(buf)
    out = cipher.decrypt(buf, sector)

    assert hashlib.sha256(out).hexdigest() == expected

    cipher = create_cipher(cipher_spec, bytes.fromhex(key))
    assert cipher.encrypt(out, sector) == buf


def test_crypto_elephant_diffuser_a() -> None:
    buffer = bytearray(b"a" * 512)
    view = memoryview(buffer)

    elephant.diffuser_a_encrypt(view, 512)

    assert hashlib.sha256(buffer).hexdigest() == "f58aa15c1219f893c4ed355d363d8f831bcc0c4a82c6bbffcca321aada9e86ec"

    elephant.diffuser_a_decrypt(view, 512)

    assert buffer == b"a" * 512


def test_crypto_elephant_diffuser_b() -> None:
    buffer = bytearray(b"a" * 512)
    view = memoryview(buffer)

    elephant.diffuser_b_encrypt(view, 512)

    assert hashlib.sha256(buffer).hexdigest() == "1d5a51ae0d0b6309f1f8661376af9ebd880b1274601f6841f5aaeb5273580133"

    elephant.diffuser_b_decrypt(view, 512)

    assert buffer == b"a" * 512


@pytest.mark.parametrize(
    ("spec", "key_size", "key_size_hint", "expected"),
    [
        ("aes", 128, None, ("aes", "cbc", 128, "plain", None)),
        ("aes-cbc", 128, None, ("aes", "cbc", 128, "plain", None)),
        ("aes-cbc", None, 256, ("aes", "cbc", 256, "plain", None)),
        ("aes-cbc", 128, 256, ("aes", "cbc", 128, "plain", None)),
        ("aes-cbc-256", 128, 256, ("aes", "cbc", 128, "plain", None)),
        ("aes-cbc-256", None, None, ("aes", "cbc", 256, "plain", None)),
        ("aes-cbc-256", 128, None, ("aes", "cbc", 128, "plain", None)),
        ("aes-cbc-256-eboiv", None, None, ("aes", "cbc", 256, "eboiv", None)),
        (
            "aes-cbc-256-essiv:sha256",
            None,
            None,
            ("aes", "cbc", 256, "essiv", "sha256"),
        ),
        ("aes-cbc-essiv:sha256", 128, None, ("aes", "cbc", 128, "essiv", "sha256")),
        ("aes-cbc-essiv:sha256", None, 128, ("aes", "cbc", 128, "essiv", "sha256")),
        ("aes-xts-plain64", None, 512, ("aes", "xts", 256, "plain64", None)),
        ("aes-xts-plain64", 128, 512, ("aes", "xts", 128, "plain64", None)),
        ("aes-xts-256-plain64", None, None, ("aes", "xts", 256, "plain64", None)),
    ],
)
def test_crypto_parse_cipher_spec(
    spec: str, key_size: int | None, key_size_hint: int | None, expected: tuple[str, str, int, str, str | None]
) -> None:
    assert parse_cipher_spec(spec, key_size, key_size_hint) == expected


def test_crypto_parse_cipher_spec_invalid() -> None:
    with pytest.raises(ValueError, match="Missing key size"):
        parse_cipher_spec("aes")

    with pytest.raises(ValueError, match="Unexpected cipher spec format"):
        parse_cipher_spec("aes-cbc-garbage-essiv")
