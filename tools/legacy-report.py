#!/usr/bin/env python3
"""
legacy-report — список старых сейфов (v1/v2, без asha) на сервере.

Показывает id сейфа, версию формата, наличие ключа записи, возраст файла
и время последнего изменения. Удаление — только руками владельца сервера.

Запуск:
    python3 tools/legacy-report.py [каталог данных]
По умолчанию каталог берётся из PASSWARIUM_DATA, иначе ../data.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA = os.environ.get('PASSWARIUM_DATA') or os.path.join(HERE, '..', 'data')


def main():
    data_dir = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath(DEFAULT_DATA)
    if not os.path.isdir(data_dir):
        print('Каталог данных не найден: %s' % data_dir)
        return 1

    now = time.time()
    legacy, modern, broken = [], [], []
    for name in sorted(os.listdir(data_dir)):
        if not (name.startswith('vault-') and name.endswith('.json')):
            continue
        path = os.path.join(data_dir, name)
        vid = name[len('vault-'):-len('.json')]
        try:
            with open(path, 'r', encoding='utf-8') as f:
                obj = json.load(f)
            st = os.stat(path)
        except (ValueError, OSError) as e:
            broken.append((vid, str(e)))
            continue
        age_days = (now - st.st_mtime) / 86400.0
        if obj.get('asha'):
            modern.append(vid)
        else:
            legacy.append({
                'id': vid,
                'v': obj.get('v', '?'),
                'wkey': 'да' if obj.get('wsha') else 'нет (ТОЛЬКО ЧТЕНИЕ)',
                'updatedAt': obj.get('updatedAt', '?'),
                'days': age_days,
            })

    print('Каталог: %s' % data_dir)
    print('Сейфов всего: %d (v3: %d, legacy: %d, битых: %d)\n'
          % (len(modern) + len(legacy) + len(broken), len(modern), len(legacy), len(broken)))

    if legacy:
        print('Legacy-сейфы (требуют миграции клиентом):')
        for it in legacy:
            print('  %-24s v=%s  ключ записи: %-22s обновлён: %s (%.0f дн. назад)'
                  % (it['id'], it['v'], it['wkey'], it['updatedAt'], it['days']))
    else:
        print('Legacy-сейфов нет.')
    if broken:
        print('\nБитые файлы (не читаются как JSON):')
        for vid, err in broken:
            print('  %s: %s' % (vid, err))
    print('\nУдаление сейфов — только вручную владельцем сервера.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
