// SHA-1 test vectors.
//
// Copyright (c) 2024 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// SHA-1 reference for "a"*i for i in 0..259.
/// Generated by:
/// echo -e "import hashlib;\nfor i in range(260):\n\th=hashlib.sha1();h.update(b'a'*i);print('    \"{}\",'.format(h.hexdigest()));"|python3
static const char *refSha1[] =
{
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
    "e0c9035898dd52fc65c41454cec9c4d2611bfb37",
    "7e240de74fb1ed08fa08d38063f6a6a91462a815",
    "70c881d4a26984ddce795f6f71817c9cf4480e79",
    "df51e37c269aa94d38f93e537bf6e2020b21406c",
    "f7a9e24777ec23212c54d7a350bc5bea5477fdbb",
    "e93b4e3c464ffd51732fbd6ded717e9efda28aad",
    "b480c074d6b75947c02681f31c90c668c46bf6b8",
    "2882f38e575101ba615f725af5e59bf2333a9a68",
    "3495ff69d34671d1e15b33a63c1379fdedd3a32a",
    "755c001f4ae3c8843e5a50dd6aa2fa23893dd3ad",
    "384fcd160ab3b33174ea279ad26052eee191508a",
    "897b99631295d204db13e863b296a09e70ab1d65",
    "128c484ff69fcdc1f82cd3781595cac5185e688f",
    "7e13c003a8256cd421055563c5da6571d50713c9",
    "3499c60eea227453c779de50fc84e217e9a53a18",
    "321a618ba6830de900738b0814d0c9f28ff2fece",
    "0478095c8ece0bbc11f94663ac2c4f10b29666de",
    "1335bfa62671b0015c6e20766c07035868edb8f4",
    "38666b8ba500faa5c2406f4575d42a92379844c2",
    "035a4ee5d60816878caec161d6cb8e00e9cc539b",
    "8c2a4e5c8f210b6aaa6c95e1c8e21351959f4541",
    "85e3737bb8ab36e2866501e517c46fffc085313e",
    "b1c76aec7674865d5346b3b0d1cb2c223c53e73e",
    "44f4647e1542a79d7d68ceb7f75d1dbf77fdebfc",
    "de8280c3a1c7db377f1ec7107c7fb62d374cc09c",
    "52a00b8461593ce33409d7c5d0411699cbf9cda3",
    "06587751ce11a8703abc64cab55b0b96d88341aa",
    "498a75f314a645671bc79a118df385d0d9948484",
    "cd762363c1c11ecb48611583520bba111f0034d4",
    "65cf771ad2cc0b1e8f89361e3b7bec2365b3ad24",
    "68f84a59a3ca2d0e5cb1646fbb164da409b5d8f2",
    "2368a1ac71c68c4b47b4fb2806508e0eb447aa64",
    "82d5343f4b2f0fcf6e28672d1f1a10c434f213d5",
    "f4d3e057abac5109b7e953578fa97968ea34f43a",
    "6c783ce5cc13ea5ce572eddfaba02f9d1bb90905",
    "9e55bf6ab8f14b37cc6f69eb7374be6c5cbd2d07",
    "1290c28910a6c12c9a131f0ecb523114f20f14c2",
    "4f5fc75bd3c93bccc09fc2de9c95442456053faf",
    "a56559418dc7908ce5f0b24b05c78e055cb863dc",
    "52cedd6b110e4330b5186478736afa5203c4f9ea",
    "32e067e0414932c3edd95fc4176a54bff1ddfe29",
    "7bd258f2f4cc4b02fca4ea157f55f6d88d26d954",
    "df51a19b291586bf46450aec1d775f3e02799b55",
    "4642fe68c57cd01fc68fc11b7f22b940328a7cc4",
    "03a4de84c189a836eaee643041b34ad2386db70d",
    "25883f7a0e732e9ab10e594ea59425dfe4d90359",
    "3e3d6e12b933133de2caa248ea12bd193a67f206",
    "1e666934c5a35f509aa31bbd9af8a37a1ed13ba6",
    "6c177354157989a2c6cd7bac80465b13bea25832",
    "aca32b501c231ef8e2d8703e71415bfbe4ccbc64",
    "e6479c70bbac662e4cc134cb8bdaade59ff55b66",
    "d9b66a0801459c8094398ef8f04700a8569c9906",
    "b05d71c64979cb95fa74a33cdb31a40d258ae02e",
    "c1c8bbdc22796e28c0e15163d20899b65621d65a",
    "c2db330f6083854c99d4b5bfb6e8f29f201be699",
    "f08f24908d682555111be7ff6f004e78283d989a",
    "5ee0f8895f4e1aae6a6661de5c432e34188a5a2d",
    "dbc8b8f59ff85a2b1448ed873484b14bf0507246",
    "13d956033d9af449bfe2c4ef78c17c20469c4bf1",
    "aeab141db28af3353283b5ccb2a322df0b9b5f56",
    "67b4b3923fa178d788a9611b76446c96431071f2",
    "03f09f5b158a7a8cdad920bddc29b81c18a551f5",
    "0098ba824b5c16427bd7a1122a5a442a25ec644d",
    "11655326c708d70319be2610e8a57d9a5b959d3b",
    "a4e77d9c0c9344921a0ac998b442ad572afdc5fb",
    "c70cc62a2ecb15f4bf1b70904dd621373d79f311",
    "dca1c821b7970a33a9a0524892ce7e49581591fd",
    "165f932eb7f82c26d8169abfe3b665d92ea8cf4a",
    "ed6c69d9e8b4373af86303dfaa3528dfbc129902",
    "0dfc17ce9eaca1570de957219f0c65c0c1f13654",
    "227c150957bf386497eb4f8eeabbaf9fe5ff5b96",
    "39c1b19d6b81461cf01a28952cc1e19c70a93851",
    "f0a70d70d40fe1f35eae75f00f4b93f70758615e",
    "0b42031e70ce2d87ef6ce621cd4b0e03cab45f70",
    "70c0661629f61a1d0c4f46d955e9bb2364077196",
    "20521047e0cb556c8107dd69ef64cf50c7ab87c8",
    "6590bb6183e647994a444556d4b62eb94cb6cfe6",
    "d6ee025dd9e8ddcb7dfcc18cbdff413101ceaa9f",
    "86f33652fcffd7fa1443e246dd34fe5d00e25ffd",
    "5832a02d8a00c665b4ec18f9dfcbe54979caa05b",
    "f4c6ed88a75ff148080b34df7f9c856018a9b754",
    "88e81577c4f9448c16f0025b53004838f7859b08",
    "14528f3adbb74803273e81411387c054d55fdbc0",
    "bddb10b89d2d10b2b96cde0b97b409348aecb8b6",
    "3082bb46204c789e26fde69e94820b28a456e623",
    "9fd7015b929e57eeace8574de6df9e901af5bd70",
    "81391dedcb14d639f798b0b7fd962dd7f8e94134",
    "9e8212145ce950d3148e92a0736639d78ffae165",
    "ec2706428417e71c758791805a187ec0075370d4",
    "ef479c1c217d542575528081b581e8ca6413ad9e",
    "a4415f768ed239e027dddedcf71f55cdedabc7b4",
    "1ae7029e40bac38a8260394b5cf2bc92b4b78573",
    "4d68135d91f016c1c12e5bf75136e23821f4db50",
    "8090cbba60f76408b23adc3c2a9889ab29fc3809",
    "01cd6c098788bf78c0d55b318fbebf5f19b31ca0",
    "7d236487f7c5c0ebb56b4bf0832a21f71fdc9f0d",
    "463a1d8c83a26ae37c83e1cc39969909a03098ab",
    "8cd96af217b5198655e73780f35d522eba762244",
    "7f9000257a4918d7072655ea468540cdcbd42e0c",
    "b48cdcf7f5d6fa3bb58f5ee6c0005678ad1e608b",
    "678b974507c4bd1f1cb519b3a825cc07e23847fa",
    "eea095c2000092abf6a500976863fc3fd9a413e8",
    "3ba90dc6eebcf1340c60682a38a41dff9046d307",
    "00aa4640b077f4dcb76aee8c18ca017493f25ea0",
    "9e22e3218c3ffd4737bf34437ee69e42aa5f8473",
    "acb445923229e517f69e007b9709d88b90fed46d",
    "dc52fb285f02dafb98a651b2c51745859a206da7",
    "1b0417cefcba7144a2bce78154312abdb5f6d8bc",
    "c74ca1df6f8dc7b6d19ac5ca15510b43dc2f1354",
    "ac877859d427d9192054eea8feb3b8a403ef83a5",
    "689993727ba37386bb032495e9dbdfb4dd1ba744",
    "3bcfff44cf3237b9b63c661a530077f794872efc",
    "387030ce32d7e3c760d4996f30cc5f96690e05a7",
    "482c2b6d0089026a36845a8ff6a63757790f9906",
    "b5bfd558d5f701656335e1b00db6fe98ffe2aa9e",
    "95f8de0eea68497781d53a368ad9cde035e8c651",
    "d0572de8e494e0b7b8e50302003fc4ae0596ef4d",
    "ee971065aaa017e0632a8ca6c77bb3bf8b1dfc56",
    "f34c1488385346a55709ba056ddd08280dd4c6d6",
    "fa6b5a6f8ac27182f838fe7841ec6d2aef3ade29",
    "05f805d3faea526f0d347b023b22042c89f63bf5",
    "c78e6ef1050c8626772a175c11d0acc5ebc33326",
    "29d2b14f43c797d078249ea7968fd19ea2a3608c",
    "3ec5ca1d740852128d4ef51e3f881f7af5c233f2",
    "1af933b8607e22788537e7350785c1a44c075512",
    "89d95fa32ed44a7c610b7ee38517ddf57e0bb975",
    "ad5b3fdbcb526778c2839d2f151ea753995e26a0",
    "d96debf1bdcbc896e6c134ea76e8141f40d78536",
    "e1cd437ec3e8a60db34e1d150a4fc73882d83b41",
    "a6a380b8230741b0ea02cfddc0d56228caddf7cd",
    "416714cfc2d392ba7df0d4b3de554d0ae5f9a7c7",
    "7fc53563e0a1c85f8d9e81f48e1eeb78edd7a14b",
    "a662bb8c73d996a25dd7c77a9a24797e5b080f7d",
    "71f9ed42b368201e6e0facebedefc3f46575b67b",
    "d8db8554295cc90abae5ce8b7595171041f2a051",
    "a59ae586b7704ca9cb92d8fc7ba95e4fc57f52d1",
    "7eebda1e4ef50254d5e806ccd18c6ac75066bbba",
    "645a899721c3f9752817bf86aed75d4383f293f7",
    "c8b41d9511bd47ebc032a5ba5eea8455e4429483",
    "569bf6b86407355db4f3ed70b0dff9000bad2454",
    "9ca3ad1419792eeeae95677c799e86f3de0e7bb7",
    "901fde599e9a5ce6b811058f074bfafbbf33614d",
    "02eb7614e4c4cfe9ed6e865bdfe1585f876b90b7",
    "cc03ade0cf56707d85330dcecde9bfa084026989",
    "0a12db11e3a5cdac18391f41cbe4623849990d30",
    "aca588b6d445bada282e8ab307b15eca46cf8f71",
    "1d03edb2f80169e9d3af120da97a5b30768cb614",
    "a5abd6b9702af8f3da86dc3124882be9a6d01b11",
    "e43157aa2bd6f7e9c797ea49441eb9ef39b5a422",
    "0b6def5d5b9d8901d6c613f18ab90181bc7f1467",
    "809a0379e7236ba53b1b50ff281a59ce7371560f",
    "634294df52c780bd7c0151264ec11c3f65fb4d71",
    "ffb7d2b87e9eb43378b68fc026d710ff69b25a1d",
    "56062f906678cc58783e3e55c8fa97adf31c6492",
    "0000945118d1301504ad395a40d4ea12667e14b3",
    "9a76ee560804191520946ef03ad6e0154bface2d",
    "e44f20c15bb05ca3da09ac53350b9ecae160ba77",
    "5e296337a3eb14c7ef4d495bd4495dc00167311c",
    "6a64fcc1fb970f7339ce886601775d2efea5cd4b",
    "6ac571c0f3103a21c783d7f135524a0487ce4d54",
    "a2d336bcd32e8ea755d7db9ab2faa9b7fdb717fb",
    "df41eb4ae30ca4ec303d2ec1fd46298fb36191ca",
    "dd4d0428c2b8ea31087a03dab1f43c0a89009075",
    "5b042dc9f655d16b8f4682178e75c974165f6cea",
    "1516b787d2d48897eee3a77d3cfee52946751838",
    "c174261a8504a876e42d63d94312a25c9330967c",
    "987ff8ef3e1725fc6ab2f471aec20b87b08008c0",
    "e7b41d4fb4cc6c5eb5afda9416c2718e273034bf",
    "8e555ee9e580c46479d5a2f6c3d4bdd5cc9fa5e4",
    "75680c173cedab4b81d544a4dacaa55da964ca41",
    "7daecf5b854aeaa0b34e40d5fb3bd7e2342d469e",
    "18db5093a476179652c91dedc3cb1478478076a0",
    "0a9ede0e79ad6e23074581ffd9ad71691691c10d",
    "0fb93da53fcb7b640ad89fdb6efa14507cb3d363",
    "accd3c08412449a2d77da65e5317399f8d969115",
    "7195585494d3dfb53054f27aaf7f224584e7a3e4",
    "8393b71c9f09718274a5d60fd9b41523cf24c51f",
    "acc431419b18ac2cdc25f23f88c0246b735d113b",
    "6707349170bff8fa01c57bbea05e1c6a6edc3773",
    "9bb51971a165372df625e90d943c071e65063872",
    "aa304715587e5ac9e6dd5e9878bf460378068963",
    "021fedbd6b884e3cdd89d7477ffe852155c37456",
    "2a4c545628c4875631e342e101f8af11cf48d252",
    "80167ddc34b5d32a8d53afa396b169ed00cc33e8",
    "30ae5873ea266205e99f6e9db75b75cbbb3394a5",
    "3579811779728998960b7faeac4858dcf922f1c9",
    "298eb68cb3b669f20340ec0db9ccc9ccb95f86da",
    "d66eced1f408c6d835abf0c90526a4b2b8a37cd3",
    "f077c7d36a72f6ecab2df866a57023199c6138a9",
    "f0d0429532d8c279879349ef6d15ec39a1f337c7",
    "9b1a580cb91c62712ce65498ebad252a1d83051d",
    "8a3a12a43de5d50c9b65809e21f11912fd66a237",
    "ccc95f6a3f3f4077b7adace983f8803414567918",
    "1d238a5ed0f185847eba49a9c0085ca183667302",
    "1a4ac3bde5a535fb07619c831c2e1e462d10f0df",
    "c6c1f2ad66da2016f73016e4d02d8a0a372c7418",
    "d6b03a3247428162d1ebc839fc34ddee3413b22c",
    "4c5da22d429fedb135ae85f65d22ae31cc4fe97e",
    "e61cfffe0d9195a525fc6cf06ca2d77119c24a40",
    "6f82e951f58a5d922ecae46ab7fcbfccecbc6849",
    "85b69533895f9c08184f1f163c9151fd47b1e49e",
    "c3fe988cdfefea20dda191468b7aacfe3ecfb345",
    "f65ceae8b9aaed19fe7c55e303c4a5d8af82e6b7",
    "87f6bec8bee30f571a968a5a8da3afb8a4170126",
    "37e13cdf37c83cdd8c578008a3644b60de65ff45",
    "5edd60ba1e20379e386025845915abd6a17b2704",
    "8474bd5d30db0c5c0309ad76d545628d5090ea95",
    "e576955fc78af54612a8d7d670dbcd0d7bef096b",
    "63dc59f7d8d17051675a44a4058ad0e1302ddecd",
    "51311dbd7c15fe4b0af22d644c9f896a48d261d9",
    "398f59dd148f98193f57a41c80b891726f46ebf7",
    "fd2c2c4219eb99a756dd53dd27a0cca87a8a9be6",
    "12151fb1044493cced54a6b87e93377bb21339db",
    "5df84a6b00c7be4a3b340c88c9f7233d894d8912",
    "c1adec5a164e04ed60056f8b996f448c05cfd8b8",
    "dc997eeb9fff6127a739784a9966ff568dded967",
    "4570cc3f369a794767f4ecdd20f420f7f81404b7",
    "91fd1a7362a88ac86cdcaf0c12196cd4ac54478d",
    "dbbc783210eaa6c7a02095c3a9914e99b7d5be05",
    "7febe42b510d93255c760521c9a1a7447f95d165",
    "2d2500b555ea06c686311dfccd68088b5c1ac4b2",
    "27ba26204d48db28360ec5f7d6aa52a1ac336a83",
    "023e576bf939e98a657997f787035e9892b1d70a",
    "6b793ffc7e56b66e733cef1ef334b859beb4a903",
    "dbf5795bac04f99f4d87231f5ee071e3e7560b88",
    "fd4b65781d6c691787b94b705318139965cff3f8",
    "75b6e6b5b384ee78096127e266bacebfdb926010",
    "06f05c4f697e324cdae3baabf44ec593d62f1bcf",
    "ce7f34fc1d00cea3c2291033001f34148ec93ef8",
    "78102ecd1085bdecc2015cbc4409266a589c0e51",
    "6679a4670829915f4c3e5aa62c9076ad905d1873",
    "9f53db04778bdc39a29a290ba8e224a3f1a76aa4",
    "847deb2731d629a2a77bd8d4d8f40cc06389fd66",
    "6eb2a0dddd1f33c727b4edec1b604e03982eabd1",
    "718b9e157887c80a219f5d394861a3c30a0c8d9f",
    "601a6c7fc730dad404ae2bdd68be69d678990473",
    "0c0dea40c49ca7d5cb20b7fef8a2884c9db420e9",
    "fdc30857cf7b957f47ebd8288d5e5d7426f44394",
    "c056f00fb97abb4c09424e3473562ff19d6e80dc",
    "90ff589d3c5c0fac624a0fee3d3b14318ba360e9",
    "6dca42bd8695b214c265b41d1d7efcd52743147c",
    "06ac3d2e7736d99e2992a099032600625f1ae29a",
    "cf1f038f744e05b321654bbfec9740a859a63106",
    "7e74fa3607830cb941af3a7fda08c5805dc6b831",
    "89331885ad350a6805940d0983567d8d2afc6b85",
    "4f29a70ace594ef0853c89c7c7522cdf8c156b92",
    "d1d8b02edb3538460a99c23d618365b0d6d79ce3",
    "f0102b8dc84689e1193c5e705f0567a504f08c0c",
    "b5d5e3e0fcccfb49d704a1e10bc97ce9761a14fe",
    "bec71b27a6b2710dedf1d7135c47f4506051f089",
    "7cb80dc70d8c28e273a8565397e98ceaf4f435ef",
    "9c49077db81495a563dad18a5c5342236089f045",
    "2ca6ff06b753061d68872bf86dfefe48d6c90031",
    "5afd9729928ad946eee5610434e66b5f95accbaf",
    "9c78512ad150c8b5d8918395ad0e5169397d2b62",
    "0c1038883670f8a0203e053eaf67dc2dec280b42",
    "57f53ed5598524493ec576770aaf3bb10063e3ce",
    "b39d82bf2b963970701bb36ce4e5fd7ddff600a6",
    nullptr
};
