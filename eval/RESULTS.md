# squatwatch name-check evaluation

## Dataset

| split | source | label | names |
|---|---|---|---|
| dev | benign | benign | 3128 |
| dev | generated | malicious | 3496 |
| exposed | incident | malicious | 18 |
| test | benign | benign | 3210 |
| test | generated | malicious | 3267 |
| test | incident | malicious | 610 |

## Threshold sweep (dev split only)

| threshold | precision | recall | F1 | FPR |
|---|---|---|---|---|
| 0.40 | 92.3% | 99.8% | 0.959 | 9.4% |
| 0.45 | 93.9% | 99.7% | 0.967 | 7.3% |
| 0.50 | 94.4% | 99.7% | 0.970 | 6.6% |
| 0.55 | 96.2% | 94.2% | 0.952 | 4.2% |
| 0.60 | 97.6% | 90.6% | 0.940 | 2.5% |
| 0.65 | 99.0% | 70.2% | 0.821 | 0.8% |
| 0.70 | 99.4% | 57.1% | 0.725 | 0.4% |
| 0.75 | 99.6% | 25.3% | 0.404 | 0.1% |
| 0.80 | 99.6% | 12.7% | 0.226 | 0.1% |
| 0.85 | 100.0% | 11.0% | 0.198 | 0.0% |
| 0.90 | 100.0% | 10.9% | 0.197 | 0.0% |

Selection rule: highest dev F1 with dev FPR <= 3%. Chosen threshold 0.60; the shipped default `min-score = 0.60` matches it.

## Held-out test results at min-score 0.60

| subset | TP | FP | FN | TN | precision | recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| all | 3259 | 82 | 618 | 3128 | 97.5% | 84.1% | 0.903 | 2.6% |
| pypi | 2036 | 47 | 461 | 1493 | 97.7% | 81.5% | 0.889 | 3.1% |
| npm | 1223 | 35 | 157 | 1635 | 97.2% | 88.6% | 0.927 | 2.1% |
| incidents + benign | 296 | 82 | 314 | 3128 | 78.3% | 48.5% | 0.599 | 2.6% |
| generated + benign | 2963 | 82 | 304 | 3128 | 97.3% | 90.7% | 0.939 | 2.6% |

## Test recall by technique (generated variants)

| ecosystem/technique | n | recall | target correct |
|---|---|---|---|
| npm/combo | 131 | 90.8% | 90.8% |
| npm/double-edit | 110 | 11.8% | 11.8% |
| npm/homoglyph | 130 | 100.0% | 100.0% |
| npm/insertion | 131 | 95.4% | 95.4% |
| npm/keyboard | 131 | 100.0% | 100.0% |
| npm/omission | 131 | 95.4% | 94.7% |
| npm/repetition | 131 | 100.0% | 100.0% |
| npm/scope | 60 | 100.0% | 100.0% |
| npm/separator | 128 | 100.0% | 100.0% |
| npm/substitution | 131 | 95.4% | 95.4% |
| npm/transposition | 131 | 100.0% | 100.0% |
| pypi/combo | 197 | 89.3% | 88.8% |
| pypi/double-edit | 150 | 6.0% | 6.0% |
| pypi/homoglyph | 197 | 100.0% | 100.0% |
| pypi/insertion | 197 | 97.5% | 97.5% |
| pypi/keyboard | 197 | 100.0% | 100.0% |
| pypi/omission | 196 | 97.4% | 96.4% |
| pypi/repetition | 197 | 100.0% | 100.0% |
| pypi/separator | 197 | 100.0% | 100.0% |
| pypi/substitution | 197 | 97.5% | 97.5% |
| pypi/transposition | 197 | 100.0% | 100.0% |

## Historical incidents (held out; development-exposed names excluded)

| incident | names | recall | target in snapshot | recall (target in snapshot) | target correct (of flagged) |
|---|---|---|---|---|---|
| iconburst-2022 | 2 | 0.0% | 1 | 0.0% | n/a |
| npm-2020-09 | 3 | 33.3% | 1 | 100.0% | 100.0% |
| npm-hacktask-2017 | 30 | 13.3% | 12 | 33.3% | 100.0% |
| pypi-2018-10 | 2 | 100.0% | 2 | 100.0% | 100.0% |
| pypi-2024-03 | 565 | 50.6% | 462 | 61.9% | 93.7% |
| skcsirt-2017 | 8 | 37.5% | 4 | 75.0% | 66.7% |
| **all incidents** | 610 | 48.5% | 482 | 61.4% | 93.6% |
| **all except pypi-2024-03** | 45 | 22.2% | 20 | 50.0% | 90.0% |

Missed incident names (314):

`BeaitifulSoop`, `BeautifilSoop`, `BeautiflulSoop`, `BeautifullSoop`, `BeautifullSooup`, `BeautySoup`, `BeuatiflSoup`, `BeutifulSoop`, `BeutifullSoup`, `Matpllotb`, `Matpllotib`, `Matplolplib`, `Matploltlab`, `Matplootib`, `Matplotlr`, `Matplottbib`, `Matplottlab`, `Matplrtib`, `PqTorch`, `PyTarch`, `PyTbrch`, `PyTcrch`, `PyThrch`, `PyTlrc`, `PyToich`, `PyTorbch`, `PyTorcdh`, `PyTorchb`, `PyTorchc`, `PyTorchg`, `PyTorchj`, `PyTorchv`, `PyTorchy`, `PyTorcm`, `PyTorqh`, `PyTroce`, `PyTrosh`, `PzTorch`, `Sijplejso`, `Simepljson`, `Simpejso`, `Simpjson`, `Siplejason`, `apidev-coop`, `asyncci`, `asynciooo`, `bibp-utils`, `bip-u8ls`, `bip-utilds`, `bip-utiles`, `bip-utilos`, `bip-utlils`, `bips-utils`, `biup-utils`, `bupi-utils`, `bzip`, `capmoneercloudclient`, `capmonsstercloudcliennt`, `capmonsstercloudclient`, `capmonsterccloudclient`, `capmonsterclouclient`, `capmonstercloudclenet`, `capmonstercloudclenit`, `capmonstercloudclent`, `capmonstercloudcliant`, `capmonstercloudclieent`, `capmonstercloudclieet`, `capmonstercloudclien`, `capmonstercloudcliend`, `capmonstercloudcliendt`, `capmonstercloudclienet`, `capmonstercloudcliennt`, `capmonstercloudclientt`, `capmonstercloudcliet`, `capmonstercloudcliient`, `capmonstercloudclinent`, `capmonstercloudclinet`, `capmonstercloudclouidclient`, `capmonstercloudcluodclient`, `capmonsterclouddclient`, `capmonsterclouddlient`, `capmonsterclouidclient`, `capmonsterclouudclient`, `capmonstercludclient`, `capmonstercoudclient`, `capmonstercouldclient`, `capmonsterrcloudclient`, `capmosterclouclient`, `capmostercloudclieent`, `capmostercloudclienet`, `capmostercloudclient`, `capmostercloudclinet`, `cloroma`, `colaroma`, `colomara`, `coloramoo`, `coloramqs`, `coloramws`, `coloramxs`, `coloramzs`, `colorhrama`, `colorm`, `colorram`, `colorramma`, `colouorama`, `cstmotkinter`, `custm`, `custmtokinter`, `customtkinet`, `customtkitenr`, `customtkitnerr`, `customtkitnre`, `customtkniterr`, `customtknster`, `custotinter`, `custotkminter`, `custotminter`, `d3.js`, `django-server`, `fabric-js`, `ffmepg`, `ionicio`, `loadyaml`, `loadyml`, `mariadb`, `mssql-node`, `mssql.js`, `node-fabric`, `node-opencv`, `node-opensl`, `node-openssl`, `node-sqlite`, `node-tkinter`, `nodecaffe`, `nodefabric`, `nodeffmpeg`, `nodemssql`, `nodesqlite`, `opencv.js`, `openssl.js`, `p-cord`, `pi-cord`, `playwrgith`, `playwritgh`, `proxy.js`, `pwd`, `py-c0ard`, `py-c0crd`, `py-c0dd`, `py-c0red`, `py-cdord`, `py-ckord`, `py-coad`, `py-cobrd`, `py-cocd`, `py-cod`, `py-codrd`, `py-coerd`, `py-cofrd`, `py-coird`, `py-cojrd`, `py-coordd`, `py-coqrd`, `py-corad`, `py-corddd`, `py-corde`, `py-cordf`, `py-cordq`, `py-cordr`, `py-cordv`, `py-cordw`, `py-cordx`, `py-corfd`, `py-corg`, `py-corid`, `py-cortd`, `py-corwd`, `py-corxd`, `py-cotrd`, `py-cowrd`, `py-cozd`, `py-cpord`, `py-crd`, `py-crodd`, `py-cwrd`, `py-cxrd`, `py-cyrd`, `py-czrd`, `pycjrd`, `pycordde`, `pycordwd`, `rensoflow`, `reqeist`, `reqeyst`, `reqirements`, `reqiremnets`, `reqiremnts`, `reqiurements`, `reqiurementstxt`, `reqiuremnets`, `requas`, `requiements`, `requierement`, `requierments`, `requiirements`, `requiirementstx`, `requiirementstxt`, `requiirementsxt`, `requiiremments`, `requiiremnts`, `requiirments`, `requiremants`, `requiremeents`, `requiremenstx`, `requiremenstxt`, `requirementss`, `requirementst`, `requirementstt`, `requirementsttx`, `requirementstx`, `requirementstxtt`, `requirementstxtx`, `requirementstxtxt`, `requirementstxx`, `requirementstxxt`, `requirementt`, `requirementtsxt`, `requirementxstxt`, `requirementxt`, `requirementxtt`, `requirementxxt`, `requiremetns`, `requiremetnstxt`, `requiremetstx`, `requiremetstxt`, `requiremments`, `requiremmentstxt`, `requiremmentxt`, `requiremmentxtxt`, `requiremnets`, `requiremnetstxt`, `requiremnetxtxt`, `requiremnts`, `requiremntstx`, `requiremntstxt`, `requiremntxtxt`, `requiremtns`, `requirmeents`, `requirment`, `requirments`, `requirmentss`, `requirmentstx`, `requirmentstxt`, `requirmentstxtt`, `requirrementstxt`, `requirtements`, `requiurement`, `requiurementstxt`, `requrementstxt`, `requriements`, `requriments`, `reuirements`, `seleenim`, `seleenimu`, `seleeniumm`, `seleiniumm`, `seleinuim`, `seleiumm`, `selemiumm`, `selemni`, `selemnim`, `selemniumm`, `selenimn`, `selennim`, `selenniumm`, `selennuim`, `selenuimm`, `seliniumm`, `seliniumn`, `selleium`, `selleniium`, `sellenim`, `selleniumm`, `sellinium`, `shadowsock`, `smb`, `sqlite.js`, `sqliter`, `sqlserver`, `telnet`, `tensnflow`, `tensofklow`, `tensofl9w`, `tensofla`, `tensoflaow`, `tensofleow`, `tensofliw`, `tensofllow`, `tensofloaw`, `tensoflod`, `tensoflolw`, `tensoflom`, `tensoflomw`, `tensoflonw`, `tensoflor`, `tensoflouw`, `tensoflpw`, `tensoflqw`, `tensoflsw`, `tensoflxow`, `tensofpow`, `tensxoflow`, `tkinter`, `umbrellaks`

## Development-exposed incident names (18), excluded from all results above

These names appear in tests, fixtures, docstrings or rule examples (`dev-exposed.txt`), so they are not held out. Their recall is biased upward and is shown only for transparency.

| set | names | recall | target in snapshot | recall (target in snapshot) | target correct (of flagged) |
|---|---|---|---|---|---|
| development-exposed only | 18 | 83.3% | 18 | 83.3% | 93.3% |
| all incidents incl. exposed | 628 | 49.5% | 500 | 62.2% | 93.6% |

| name | incident | score | flagged |
|---|---|---|---|
| `babelcli` | npm-hacktask-2017 | 0.70 | yes |
| `colourama` | pypi-2018-10 | 0.70 | yes |
| `cross-env.js` | npm-hacktask-2017 | 0.62 | yes |
| `crossenv` | npm-hacktask-2017 | 0.70 | yes |
| `dajngo` | pypi-2018-10 | 0.78 | yes |
| `djanga` | pypi-2018-10 | 0.68 | yes |
| `electorn` | npm-2020-09 | 0.66 | yes |
| `jeIlyfish` | pypi-2019-12 | 0.90 | yes |
| `jquery.js` | npm-hacktask-2017 | 0.62 | yes |
| `mongose` | npm-hacktask-2017 | 0.70 | yes |
| `mysqljs` | npm-hacktask-2017 | 0.44 | no |
| `noderequest` | npm-hacktask-2017 | 0.58 | no |
| `nodesass` | npm-hacktask-2017 | 0.64 | yes |
| `python3-dateutil` | pypi-2019-12 | 0.81 | yes |
| `setup-tools` | skcsirt-2017 | 0.82 | yes |
| `tensoflw` | pypi-2024-03 | 0.50 | no |
| `twilio-npm` | npm-2020-11 | 0.62 | yes |
| `urlib3` | skcsirt-2017 | 0.82 | yes |

## Benign names flagged on test (82), highest score first

| name | ecosystem | score | looks like | techniques |
|---|---|---|---|---|
| `findup` | npm | 0.82 | find-up | separator |
| `ipytest` | pypi | 0.76 | pytest | insertion |
| `typescript-eslint-parser` | npm | 0.76 | @typescript-eslint/parser | scope-flatten |
| `uglifyjs` | npm | 0.76 | uglify-js | separator |
| `pymantic` | pypi | 0.74 | pydantic | substitution |
| `yaml-js` | npm | 0.74 | js-yaml | token-order |
| `pytrie` | pypi | 0.70 | pygtrie | omission |
| `vue-server-renderer` | npm | 0.70 | @vue/server-renderer | scope-flatten |
| `mimer` | npm | 0.70 | immer | transposition |
| `debug-log` | npm | 0.70 | debuglog | separator |
| `rollup-plugin-replace` | npm | 0.70 | @rollup/plugin-replace | scope-flatten |
| `file-save` | npm | 0.70 | file-saver | omission |
| `babel-plugin-transform-react-constant-elements` | npm | 0.70 | @babel/plugin-transform-react-constant-elements | scope-flatten |
| `string` | npm | 0.70 | astring | omission |
| `pyinvoke` | pypi | 0.69 | invoke | combo, edit-2 |
| `http2-proxy` | npm | 0.69 | http-proxy | insertion, combo |
| `zai-sdk` | pypi | 0.68 | xai-sdk | keyboard |
| `property-cached` | pypi | 0.68 | cached-property | token-order |
| `zccache` | pypi | 0.68 | sccache | keyboard |
| `formulae` | pypi | 0.68 | formulas | keyboard |
| `kubernetes-client` | pypi | 0.68 | kubernetes | combo |
| `dnutils` | pypi | 0.68 | dbutils | keyboard |
| `urlman` | pypi | 0.68 | uroman | keyboard |
| `pyjdbc` | pypi | 0.68 | pyodbc | substitution |
| `pylink` | pypi | 0.68 | pylint | substitution |
| `fs-promise` | npm | 0.68 | is-promise | substitution |
| `webpack-core` | npm | 0.68 | webpack | combo |
| `eslint-plugin-import-helpers` | npm | 0.68 | eslint-plugin-import | combo |
| `autoprefixer-core` | npm | 0.68 | autoprefixer | combo |
| `jslint` | npm | 0.68 | eslint | substitution |
| `tools` | pypi | 0.66 | toolz | keyboard |
| `anarcii` | pypi | 0.66 | anarci | repetition |
| `pinject` | pypi | 0.64 | inject | insertion |
| `siphash` | pypi | 0.64 | siphashc | omission |
| `html4docx` | pypi | 0.64 | htmldocx | insertion |
| `aliyun-python-sdk-cs` | pypi | 0.64 | aliyun-python-sdk-ecs | omission |
| `prompt` | pypi | 0.64 | prompty | omission |
| `emcache` | pypi | 0.64 | memcache | omission |
| `html2docx` | pypi | 0.64 | htmldocx | insertion |
| `filemagic` | pypi | 0.64 | file-magic | separator |
