# Contracts that governed execution while named in no signed order

From the pinned run in `intent_gap.json`: 174 CoW settlements, end block 25660951, 7 windows of 25 spaced 45 days.

- **77 distinct contracts**
- **14 have no published source.** At the moment these decide what happens to a user's approved balance, a code-reading defense has nothing to read.
- **10 are proxy-shaped**, so the source that can be read is not necessarily the code that will run.
- **34 were under a year old** at the start of the sample. A defense holding a fixed allowlist of known-good execution venues would be perpetually stale.

Both of the first two are the failure shapes the historical corpus shows, recovered here at a site with different mechanics, a different signer model and a different adversary.

| contract | name | settlements | verified | proxy | created block |
|---|---|---:|---|---|---:|
| `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` | WETH9 | 37 | yes | no | 4719568 |
| `0x0e91b5b157e98c20b90332cc3b9cf4ae67b222ad` | DeadlineCheck | 36 | yes | no | 23942667 |
| `0x111111125421ca6dc452d289314280a0f8842a65` | AggregationRouterV6 | 31 | yes | no | 19212918 |
| `0xbbbbbbb520d69a9775e85b458c58c648259fad5f` | BebopSettlement | 29 | yes | no | 19783283 |
| `0x60bf78233f48ec42ee3f101b9a05ec7878728006` | HooksTrampoline | 22 | yes | no | 23031383 |
| `0xd524f98f554bd34f4185678f64a85bb98971d314` | — | 21 | **no** | no | 23125345 |
| `0xba3cb449bd2b4adddbc894d8697f5170800eadec` | CoWSwapEthFlow | 19 | yes | no | 21674096 |
| `0x66a9893cc07d91d95644aedd05d03f95e1dba8af` | UniversalRouter | 16 | yes | no | 21689092 |
| `0xbc1d9760bd6ca468ca9fb5ff2cfbeac35d86c973` | — | 15 | **no** | no | 24028793 |
| `0x55084ee0fef03f14a305cd24286359a35d735151` | HashflowRouter | 9 | yes | no | 18059492 |
| `0xf08d4dea369c456d26a3168ff0024b904f2d8b91` | BCoWPool | 8 | yes | no | 20476566 |
| `0xba12222222228d8ba445958a75a0704d566bf2c8` | Vault | 7 | yes | no | 12272146 |
| `0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2` | InitializableImmutableAdminUpgradeabilityProxy | 7 | yes | **yes** | 16291127 |
| `0x80b4a27276d0c9cce34bf984877c5c9ed5982a9f` | — | 6 | **no** | no | 24789935 |
| `0xa929c559e5e6537359680f39cb4e3708e1a14dd1` | AggregatorGuard | 6 | yes | no | 24420911 |
| `0x3de27efa2f1aa663ae5d458857e731c129069f29` | WeightedPool | 6 | yes | no | 17663805 |
| `0xa540ec8c73322200d68e1b86c471a5c850854f22` | NativeRouter | 6 | yes | no | 23189574 |
| `0x7a250d5630b4cf539739df2c5dacb4c659f2488d` | UniswapV2Router02 | 6 | yes | no | 10207858 |
| `0x0000000000001ff3684f28c67538d4d072c22734` | AllowanceHolder | 6 | yes | no | 19582162 |
| `0xfe470834f297a227e0856e5a7ea637582c061ec5` | — | 6 | **no** | no | 23640395 |
| `0xfd0b31d2e955fa55e3fa641fe90e08b677188d35` | TychoRouter | 5 | yes | no | 22575004 |
| `0x6131b5fae19ea4f9d964eac0408e4408b66337b5` | MetaAggregationRouterV2 | 5 | yes | no | 16366767 |
| `0xdef1c0ded9bec7f1a1670819833240f027b25eff` | ZeroEx | 5 | yes | **yes** | 10247094 |
| `0x7a819fa46734a49d0112796f9377e024c350fb26` | KyberSwapRFQ | 5 | yes | no | 18182728 |
| `0x55c64ae908a9c770c163b0dfdfd74ede2158e83f` | — | 4 | **no** | no | 24918727 |
| `0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45` | SwapRouter02 | 4 | yes | **yes** | 13804681 |
| `0x7a50a89550c4b142d1df57ec47b9cb3386d852da` | — | 4 | **no** | **yes** | 25186241 |
| `0x000000000022d473030f116ddee9f6b43ac78ba3` | Permit2 | 4 | yes | no | 15986406 |
| `0x96fb3209fb4da072fb5cc493fa0ff4ea5eaa2d41` | — | 3 | **no** | no | 24275491 |
| `0x39d1d8fcc5e6eeaf567bce4e29b94fec956d3519` | SwapV2Router | 2 | yes | no | 20245558 |
| `0x5c6ee304399dbdb9c8ef030ab642b10820db8f56` | WeightedPool2Tokens | 2 | yes | no | 12369384 |
| `0x13f4ea83d0bd40e75c8222255bc855a974568dd4` | SmartRouter | 2 | yes | **yes** | 16944997 |
| `0x7f86bf177dd4f3494b841a37e810a34dd56c829b` | CurveTricryptoOptimizedWETH | 2 | yes | no | 17371455 |
| `0x9d0e8cdf137976e03ef92ede4c30648d05e25285` | BCoWPool | 2 | yes | no | 20587725 |
| `0x5e1f62dac767b0491e3ce72469c217365d5b48cc` | DexRouter | 2 | yes | no | 23894108 |
| `0xa4c567c662349bec3d0fb94c4e7f85ba95e208e4` | Vyper_contract | 2 | yes | no | 17817797 |
| `0xf6e72db5454dd049d0788e411b06cfaf16853042` | DssLitePsm | 2 | yes | no | 20283666 |
| `0xb576491f1e6e5e62f1d8f26062ee822b40b0e0d4` | Vyper_contract | 2 | yes | no | 13783426 |
| `0x9995855c00494d039ab6792f18e368e530dff931` | Router | 2 | yes | no | 22047306 |
| `0x91331b6dd589163af02fb13e0466c3ba10ee310f` | — | 2 | **no** | no | 23689565 |
| `0xa356867fdcea8e71aeaf87805808803806231fdc` | DODOV2Proxy02 | 1 | yes | no | 11730395 |
| `0xc42b7df84bc61ab7461b78ed4e81c1284e139024` | — | 1 | **no** | no | 25636522 |
| `0xa1c7a8360eb4049595a24d6919e74e105b409cb5` | CurveRouterV2 | 1 | yes | no | 25041924 |
| `0x342b8458161137d0203605fa51e4363c1445adcd` | KipseliPropAMMWrapper | 1 | yes | no | 25043243 |
| `0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f` | UniswapV2Router02 | 1 | yes | no | 10794261 |
| `0xcabd955322dfbf94c084929ac5e9eca3feb5556f` | BeaconProxy | 1 | yes | **yes** | 22985314 |
| `0x3c59a38e9ea02a48f7bda8ea2dd5a38831371d31` | — | 1 | **no** | no | 24832578 |
| `0x28b1dc1a5e3699a428bc51d234dfab7c9cb2a183` | DexRouter | 1 | yes | no | 24696000 |
| `0x7529d8ac08d4dddc159bc8809a971a7605c34f80` | BCoWPool | 1 | yes | no | 21688115 |
| `0x33b2faf0d58fd2b5caba371b990826e3d021662f` | — | 1 | **no** | no | 24841414 |
| `0x232ce3bd40fcd6f80f3d55a522d03f25df784ee2` | Lighter | 1 | yes | no | 23669741 |
| `0xe592427a0aece92de3edee1f18e0157c05861564` | SwapRouter | 1 | yes | **yes** | 12369634 |
| `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48` | FiatTokenProxy | 1 | yes | **yes** | 6082465 |
| `0xd26f20001a72a18c002b00e6710000d68700ce00` | MEVCaptureRouter | 1 | yes | no | 24155249 |
| `0xd51a44d3fae010294c616388b506acda1bfaae46` | Vyper_contract | 1 | yes | no | 12821148 |
| `0xdb74dfdd3bb46be8ce6c33dc9d82777bcfc3ded5` | CurveStableSwapNG | 1 | yes | no | 19714579 |
| `0xeac874aed7761460dd4c89778ba6db7d320911a8` | CurveStableSwapNG | 1 | yes | no | 19171341 |
| `0xcd5fe23c85820f7b72d0926fc9b05b43e359b7ee` | UUPSProxy | 1 | yes | **yes** | 17664336 |
| `0x92762b42a06dcdddc5b7362cfb01e631c4d44b40` | WeightedPool | 1 | yes | no | 14475162 |
| `0x40a50cf069e992aa4536211b23f286ef88752187` | CoWSwapEthFlow | 1 | yes | no | 16169866 |
| `0x57e114b691db790c35207b2e685d4a43181e6061` | ENA | 1 | yes | no | 19371662 |
| `0xdac17f958d2ee523a2206206994597c13d831ec7` | TetherToken | 1 | yes | no | 4634748 |
| `0xe2f6127b5c93a95415af14df900db52a509cf590` | BCoWPool | 1 | yes | no | 24507370 |
| `0xf9078fb962a7d13f55d40d49c8aa6472abd1a5a6` | Vyper_contract | 1 | yes | no | 15724002 |
| `0xd65ed4bce447195187f37ce7d82f56adf1826f8f` | CurveStableSwapNG | 1 | yes | no | 21249565 |
| `0xbeb0b0623f66be8ce162ebdfa2ec543a522f4ea6` | JamSettlement | 1 | yes | no | 21444718 |
| `0x6b175474e89094c44da98b954eedeac495271d0f` | Dai | 1 | yes | no | 8928158 |
| `0xa188eec8f81263234da3622a406892f3d630f98c` | UsdsPsmWrapper | 1 | yes | no | 20668728 |
| `0x62e31802c6145a2d5e842eed8efe01fc224422fa` | MaverickV2Router | 1 | yes | no | 20027244 |
| `0x5426178799ee0a0181a89b4f57efddfab49941ec` | CurveTricryptoOptimizedWETH | 1 | yes | no | 17591884 |
| `0xc26b84a5aa0b4fb8a7cff41153d37f2681ad88cc` | — | 1 | **no** | no | 23095687 |
| `0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9` | InitializableAdminUpgradeabilityProxy | 1 | yes | **yes** | 10926829 |
| `0x4fae7c4ad38e1f4a343780ce791678be8011b225` | — | 1 | **no** | no | 20494123 |
| `0x93d199263632a4ef4bb438f1feb99e57b4b5f0bd` | ComposableStablePool | 1 | yes | no | 17915001 |
| `0x3d0d331390d14df42c16fc20700f7e6ad4849c50` | CurveTwocryptoOptimized | 1 | yes | no | 21215358 |
| `0x0c95ea31e4501b3b879cae2232087e478d44aeab` | MEVResistRouter | 1 | yes | no | 22695305 |
| `0x7b0a7a4add86c41650040a0574cf6201dda42e20` | — | 1 | **no** | no | 23475616 |

*Powered by Etherscan.io APIs.*
