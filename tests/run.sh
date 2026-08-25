#!/bin/sh
# Стенды репозитория. Ни один не требует сети: всё считается по схеме и по выпущенным
# файлам в lists/. Прогон — единицы секунд, поэтому шаг стоит в validate.yml.
#
# Чего эти стенды НЕ сторожат: опубликованные сборкой списки. validate.yml запускается на
# push в main, но автокоммит сборки идёт под secrets.GITHUB_TOKEN, а такой push workflow не
# запускает вовсе. То есть здесь проверяется только то, что толкают руками; публикуемые
# данные сторожит гейт внутри самой сборки (generator/aggregate.py).
set -e
cd "$(dirname "$0")/.."
fail=0
for t in tests/gate_shared_proxy.py tests/precheck_states.py; do
  echo "--- $t"
  python3 "$t" || fail=1
done
[ "$fail" = 0 ] && echo "все стенды зелёные" || echo "есть провалившиеся стенды"
exit $fail
