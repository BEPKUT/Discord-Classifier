import re
import sys
from collections import defaultdict

def expected_scenario_from_filename(filename: str) -> str:
    name_lower = filename.lower()
    if name_lower.startswith('audiocall'):
        return 'Audio Call'
    if name_lower.startswith('autherization') or name_lower.startswith('authorization'):
        return 'Authorization'
    if name_lower.startswith('registration'):
        return 'Registration'
    if name_lower.startswith('screendemonstration'):
        return 'Screen Sharing'
    if name_lower.startswith('sendfile'):
        return 'Upload файла'
    if name_lower.startswith('sendmessage'):
        return 'Отправка сообщения'
    if name_lower.startswith('takeanddowlandfile'):
        return 'Download файла'
    if name_lower.startswith('takemessage'):
        return 'Приём сообщения'
    if name_lower.startswith('videocall'):
        return 'Video Call'
    return 'Unknown'

def parse_scenarios_for_file(lines):
    text = ''.join(lines)
    block_pattern = re.compile(r'^\s*\d+\)\s*$', re.MULTILINE)
    blocks = block_pattern.split(text)

    scenario_labels = []
    ignored = {'Unknown', 'Unknown / Mixed traffic'}

    for block in blocks:
        if not block.strip():
            continue
        scen = None
        direction = None
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith('Сценарий'):
                parts = stripped.split(None, 1)
                if len(parts) > 1:
                    scen = parts[1]
            elif stripped.startswith('Направление'):
                parts = stripped.split(None, 1)
                if len(parts) > 1:
                    direction = parts[1]

        if scen is None:
            continue

        if scen == 'Сообщение':
            if direction == 'Приём сообщения':
                label = 'Приём сообщения'
            elif direction == 'Отправка сообщения':
                label = 'Отправка сообщения'
            else:
                label = 'Отправка сообщения'
        elif scen == 'Отправка сообщения':
            label = 'Отправка сообщения'
        elif scen == 'Приём сообщения':
            label = 'Приём сообщения'
        elif scen == 'Файл':
            if direction == 'Отправка':
                label = 'Upload файла'
            elif direction == 'Приём':
                label = 'Download файла'
            else:
                label = 'Upload файла'
        else:
            label = scen

        if label not in ignored:
            scenario_labels.append(label)

    return scenario_labels

def analyze_file(filepath, mode=1):
    with open(filepath, 'r', encoding='utf-8') as f:
        all_lines = f.readlines()

    total_files = 0
    correct_files = 0
    stats = defaultdict(lambda: {'total': 0, 'correct': 0})
    extra_scenarios = 0
    extra_by_type = defaultdict(int)

    filename_re = re.compile(r'^(\S+\.(?:pcap|pcapng))\s*$')

    current_filename = None
    current_file_lines = []

    for line in all_lines:
        match_fn = filename_re.match(line.rstrip('\n'))
        if match_fn:
            if current_filename is not None:
                expected = expected_scenario_from_filename(current_filename)
                if expected != 'Unknown':
                    detected = parse_scenarios_for_file(current_file_lines)
                    total_files += 1
                    stats[expected]['total'] += 1

                    extra = [s for s in detected if s != expected]
                    extra_scenarios += len(extra)
                    for s in extra:
                        extra_by_type[s] += 1

                    if mode == 1:
                        is_correct = expected in detected
                    else:
                        is_correct = (expected in detected) and (len(extra) <= 2)

                    if is_correct:
                        correct_files += 1
                        stats[expected]['correct'] += 1

            current_filename = match_fn.group(1)
            current_file_lines = []
        else:
            if current_filename is not None:
                current_file_lines.append(line)

    if current_filename is not None:
        expected = expected_scenario_from_filename(current_filename)
        if expected != 'Unknown':
            detected = parse_scenarios_for_file(current_file_lines)
            total_files += 1
            stats[expected]['total'] += 1

            extra = [s for s in detected if s != expected]
            extra_scenarios += len(extra)
            for s in extra:
                extra_by_type[s] += 1

            if mode == 1:
                is_correct = expected in detected
            else:
                is_correct = (expected in detected) and (len(extra) <= 2)

            if is_correct:
                correct_files += 1
                stats[expected]['correct'] += 1

    mode_names = {1: "текущий анализ (ожидаемый сценарий присутствует)",
                  2: "чистый анализ (ожидаемый сценарий присутствует и лишних ≤ 2)"}
    print("\n\n" + "=" * 70)
    print("ИТОГОВЫЙ ОТЧЁТ О КОРРЕКТНОСТИ КЛАССИФИКАЦИИ")
    print(f"Режим: {mode_names.get(mode, 'неизвестный')}")
    print("=" * 70)
    print(f"Всего проанализировано файлов: {total_files}")
    print(f"Верно классифицировано: {correct_files}")
    if total_files > 0:
        print(f"Общая точность: {correct_files/total_files*100:.1f}%\n")
    else:
        print("Нет данных для анализа\n")
        return

    print("Точность по типам сценариев:")
    for sc in sorted(stats.keys()):
        total = stats[sc]['total']
        correct = stats[sc]['correct']
        if total > 0:
            acc = correct / total * 100
            print(f"  {sc:20} : {correct:3} / {total:3} ({acc:5.1f}%)")
        else:
            print(f"  {sc:20} : нет данных")

    print("\n" + "=" * 70)
    print("ЛИШНИЕ СЦЕНАРИИ (не соответствующие ожидаемому для файла)")
    print("=" * 70)
    print(f"Всего лишних сценариев: {extra_scenarios}")
    if total_files > 0:
        print(f"В среднем на файл: {extra_scenarios / total_files:.2f}")

    if extra_by_type:
        print("\nРаспределение лишних сценариев по типам:")
        for sc, cnt in sorted(extra_by_type.items(), key=lambda x: -x[1]):
            print(f"  - {sc}: {cnt} раз(а)")

    print("=" * 70)

if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Использование: python check_classification.py <файл_с_результатами.txt> [режим]")
        print("  режим: 1 - текущий анализ (по умолчанию), 2 - чистый анализ (extra ≤ 2)")
        sys.exit(1)

    filepath = sys.argv[1]
    mode = 1
    if len(sys.argv) == 3:
        try:
            mode = int(sys.argv[2])
        except ValueError:
            print("Режим должен быть 1 или 2")
            sys.exit(1)
        if mode not in (1, 2):
            print("Режим должен быть 1 или 2")
            sys.exit(1)

    analyze_file(filepath, mode)