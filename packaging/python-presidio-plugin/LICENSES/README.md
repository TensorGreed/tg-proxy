# Third-party licenses

This package depends on the following open-source components, all under permissive licenses. Their full license text is reproduced when the package is built into a wheel; this directory should be populated at release time from upstream sources.

| Component | Project | License | URL |
|---|---|---|---|
| `presidio-analyzer` | Microsoft Presidio | MIT | https://github.com/microsoft/presidio/blob/main/LICENSE |
| `spacy` | Explosion AI | MIT | https://github.com/explosion/spaCy/blob/master/LICENSE |
| `en_core_web_lg` / `_md` / `_sm` | spaCy English models | MIT | https://github.com/explosion/spacy-models/blob/master/LICENSE |
| `phonenumbers` | Google libphonenumber (Python port) | Apache 2.0 | https://github.com/daviddrysdale/python-phonenumbers/blob/dev/LICENSE |
| `regex` | mrabarnett | Apache 2.0 / Public Domain | https://github.com/mrabarnett/mrab-regex/blob/hg/LICENSE.txt |
| `tgproxy-plugin` | TensorGreed (this repo) | MIT | ../../../../LICENSE |

## Compliance

MIT and Apache 2.0 both require preservation of the copyright notice and license text. The release-time wheel build should copy each upstream `LICENSE` file into this directory before packaging so the resulting `.whl` ships compliant. Today this directory is a placeholder; populate it as part of the publish workflow.

Neither MIT nor Apache 2.0 requires source disclosure of derived work.
