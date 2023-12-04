## 18 - Number Encryptor

### Description

**Solve**: 2/242

**Score**: 98

The basic of RSA for everyday life.

[https://stdio-2026-public.2600.in.th/number_encryptor.zip](https://stdio-2026-public.2600.in.th/number_encryptor.zip)

Author: Sudlit

 `number-encryptor-stdio.2600.in.th`

### Solution

Upon reviewing the code, I could say with my (little) experience that this is just an normal RSA implementation so there really no error in RSA implementation here, but other than `/encrypt` and `/decrypt` there's the `/very_secret_endpoint` that will respond with encrypted flag using random generated key on the server

```python
@app.route('/very_secret_endpoint', methods=['POST'])
def secret():
    secret = pow(bytes_to_long(FLAG.encode()), e, n)
    return render_template('index.html', result=secret)
```

We can simply use `curl` to get it

```bash
$ curl -s -XPOST https://number-encryptor-stdio.2600.in.th/very_secret_endpoint | grep -oP '<code>\K\d+'
30689880504302205046005456591074483547590841643642132970938107881111216897985480368330010654091935230047762275766492692576656478004263492208484915861986757915464773607314038232092753597605043834130750107223417512401577357695764240735756201552421673565404344626945883726443708737577808164282465862436480376702
```

If this is a normal website, we could just feed it into decrypt function but as in the source code if the message have `STDIO` in it, it will redirect us to classic rick roll...

To comprehend how to bypass this, we need to understand what is really going on here:

```python
@app.route('/encrypt', methods=['POST'])
def encrypt():
    num = request.form.get('input_num')
    if num.isdigit():
        enc = pow(int(num), e, n)
    ...

def decrypt():
    num = request.form.get('input_num')
    if num.isdigit():
        dec = pow(int(num), d, n)
    ...
```

It can be observed that RSA encryption involves raising our message to the power of `e` and taking the modulus `n`. During decryption, it entails raising the encrypted flag to the power of `d` and again taking the modulus `n`. By leveraging the properties of exponentiation, we can square the encrypted message. Subsequently, we have the server decrypt it, resulting in the server seeing a message raised to the power of 2, not the original message. We can then square root the server's response to retrieve the original flag.

```
30689880504302205046005456591074483547590841643642132970938107881111216897985480368330010654091935230047762275766492692576656478004263492208484915861986757915464773607314038232092753597605043834130750107223417512401577357695764240735756201552421673565404344626945883726443708737577808164282465862436480376702**2 = 941868765368348567515317898513901346212867219010566045545245656421620668689124951584261399532059524335001240583697897132825464888659625411647991320838571439675149607375891137193904893566258032177940979704296941020174663973426084169278893086946110430113788339116635460553297893234962316998623251211705465940917423916119696495201733458529877970611586451329151870150374065202347971365543832491815874950172928713193952127379135929974715203589929537310065469871928263567543600461833625603902364167114427932851805861384575927737468584797481531195639297502572862404246753831628663461442840358406646148945413493919824396804
```

![](https://github.com/nkd3v/STDiO-CTF-2023-Writeup/assets/28519551/bfa342dd-ab67-46dd-a3d8-3a1b63aa529c)

```python
import math

flag_int = math.isqrt(8917253179001425999828352203138179088722714419448347439330903321052925447155989550907953075233798207408322657497745304351557959558194924319402423933949279892508963077294320840566634249830735296343430574145396489)

flag = bytes.fromhex(hex(flag_int)[2:]).decode()

print(flag)
```

`STDIO23_18{ee0872162641b48513284fed034b667e}`