#!/usr/bin/env python3
import hashlib
import base64
import string
import itertools
import os
import time
import multiprocessing

OUTPUT_FILE = "vysledky.txt"
HEARTBEAT_INTERVAL = 60

def worker_optimized_generator(args):
    prefix, suffix_len, charset, targets_bin = args
    found = []
    prefix_bytes = prefix.encode('utf-8')
    base_m = hashlib.md5(prefix_bytes)

    for suffix_tuple in itertools.product(charset, repeat=suffix_len):
        suffix_str = "".join(suffix_tuple)
        suffix_bytes = suffix_str.encode('utf-8')
        m_pass = base_m.copy()
        m_pass.update(suffix_bytes)

        for salt_bytes, target_hash_bytes, login, fname in targets_bin:
            m_final = m_pass.copy()
            m_final.update(salt_bytes)
            if m_final.digest() == target_hash_bytes:
                found.append((fname, login, prefix + suffix_str))
    return found

def log_result(message):
    print(message)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def load_shadow_files(directory):
    targets = []
    files = sorted([f for f in os.listdir(directory) if f.startswith("shadow") and f.endswith(".txt")])
    for filename in files:
        filepath = os.path.join(directory, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line: continue
                parts = line.split(':')
                if len(parts) == 3:
                    login, salt, pwhash = parts
                    targets.append({
                        'file': filename, 'login': login,
                        'salt_bytes': salt.encode('utf-8'),
                        'hash_bytes': base64.b64decode(pwhash),
                        'cracked': None, 'cats_found': set()
                    })
    return targets

def get_category1_candidates():
    base_names = [
        "alexander", "alexandra", "adam", "adela", "adrian", "adriana", "alica", "alenka", "alena", "andrea", "andrej",
        "anna", "anezka", "anton", "barbora", "beata", "benjamin", "berta", "blanka", "bohumil", "bohumir", "bozena",
        "branislav", "branko", "brigita", "cyril", "dagmar", "dalibor", "dana", "daniela", "daniel", "darina", "david",
        "denisa", "denis", "dezider", "diana", "dionyz", "dobroslav", "dominika", "dominik", "drahomir", "dusan", "dusana",
        "edita", "eduard", "elena", "eleonora", "elizabeth", "ela", "emil", "emilia", "erik", "erika", "estera", "eva",
        "evzen", "filip", "frantisek", "frantiska", "gabriel", "gabriela", "gaspar", "gejza", "gerda", "gizela", "gustav",
        "hana", "hedviga", "helena", "henrich", "hilda", "hubert", "hugo", "ida", "ignac", "imrich", "irena", "ivan",
        "ivana", "iveta", "ivica", "izabela", "jakub", "jan", "janka", "jarmila", "jaroslav", "jaroslava", "jela",
        "jozef", "jozefina", "judita", "julia", "julius", "juraj", "justina", "kamila", "kamil", "karol", "karolina",
        "katarina", "kazimir", "klara", "klaudia", "klement", "koloman", "konstantin", "kornel", "kristian", "kristina",
        "krystof", "kveta", "ladislav", "laura", "lea", "lenka", "leonard", "leopold", "libusa", "linda", "livia", "lucia",
        "ludmila", "ludovit", "lukas", "lydia", "magdalena", "malvina", "marcela", "marek", "margita", "marian", "maria",
        "marta", "martin", "martina", "matej", "matus", "maximilian", "metod", "michaela", "michal", "mikulas", "milada",
        "milan", "miloslav", "milos", "miroslav", "miroslava", "monika", "natalia", "nela", "nikola", "nina", "nora",
        "norbert", "oldrich", "olga", "oliver", "ondrej", "oskar", "oto", "pankrac", "patrik", "patricia", "pavol",
        "pavel", "petra", "peter", "petronela", "pravoslav", "prokop", "radovan", "radoslav", "rastislav", "rebecca",
        "regina", "renata", "rene", "richard", "robert", "roman", "romana", "rozalia", "rudolf", "rut", "sabina",
        "samuel", "servac", "severin", "silvester", "silvia", "simona", "simon", "slavka", "slavomir", "sona",
        "stanislav", "stela", "svatopluk", "svetlana", "simon", "span", "stefan", "stefania", "tamara", "tatiana",
        "terezia", "tibor", "timotej", "tomas", "ulrika", "urban", "ursula", "vaclav", "valentin", "valeria", "vanda",
        "vavrinec", "vendelin", "veronika", "viera", "viktoria", "viktor", "viliam", "vincent", "viola", "vit",
        "vladimir", "vladislav", "vlasta", "vojtech", "xenia", "zoltan", "zora", "zuzana", "zigmund", "zofia"
    ]

    suffixes = ["ka", "ko", "ko", "icka", "ik", "uska", "ko", "ulo", "o", "usa", "inka"]

    all_words = set()
    for name in base_names:
        name = name.lower()
        all_words.add(name)

        stem = name[:3] if len(name) > 3 else name
        stem4 = name[:4] if len(name) > 4 else name

        for sfx in suffixes:
            all_words.add(stem + sfx)
            all_words.add(stem4 + sfx)

        all_words.update([
            name + "ko", name + "ka", name + "ik",
            "misko", "ferko", "janko", "katka", "zuzka", "evka", "lucka", "petko",
            "samko", "matko", "jozko", "matusko", "kubko", "petik", "janik"
        ])

    final_candidates = set()
    for word in all_words:
        clean_word = word.replace('a','a').replace('c','c').replace('d','d').replace('e','e').replace('i','i').replace('l','l').replace('n','n').replace('o','o').replace('r','r').replace('s','s').replace('t','t').replace('u','u').replace('y','y').replace('z','z')

        for w in [word, clean_word]:
            final_candidates.add(w.lower())
            for i in range(len(w)):
                variant = w[:i] + w[i].upper() + w[i+1:]
                final_candidates.add(variant)

    return list(final_candidates)

def check_all_files_satisfied(targets, category_label):
    all_files = set(t['file'] for t in targets)
    files_with_cat = set(t['file'] for t in targets if category_label in t['cats_found'])
    return all_files.issubset(files_with_cat)

def run_dictionary_attack(targets, candidates):
    log_result(f"\n[Category 1] Dictionary Attack...")
    start = time.time()
    category_label = "Category 1"
    for t in targets:
        for cand in candidates:
            m = hashlib.md5(cand.encode('utf-8'))
            m.update(t['salt_bytes'])
            if m.digest() == t['hash_bytes']:
                t['cracked'] = cand
                t['cats_found'].add(category_label)
                log_result(f"  [+] CRACKED: {t['file']} | {t['login']} | {cand}")
                break
    log_result(f"Phase Category 1 duration: {time.time()-start:.2f}s")

def run_generic_brute_force(targets, length, charset, category_label):
    if check_all_files_satisfied(targets, category_label):
        print(f"\n[{category_label}] Condition (1 password/file) already met. Skipping length {length}.")
        return

    active_targets_bin = [
        (t['salt_bytes'], t['hash_bytes'], t['login'], t['file'])
        for t in targets if not t['cracked']
    ]

    if not active_targets_bin:
        log_result(f"\n[{category_label}] No remaining hashes.")
        return

    print(f"\n[{category_label}] Brute force: length {length}...")
    cores = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(processes=cores)
    tasks = [(char, length - 1, charset, active_targets_bin) for char in charset]

    start_time = time.time()
    last_heartbeat = start_time
    stop_early = False

    try:
        iterator = pool.imap_unordered(worker_optimized_generator, tasks)
        while not stop_early:
            try:
                result_list = iterator.next(timeout=1)
                for fname, login, password in result_list:
                    for t in targets:
                        if t['login'] == login and t['file'] == fname and not t['cracked']:
                            t['cracked'] = password
                            t['cats_found'].add(category_label)
                            log_result(f"  [+] CRACKED {category_label}: {fname} | {login} | {password}")

                    if check_all_files_satisfied(targets, category_label):
                        log_result(f"  [!] Condition for {category_label} met for all files. Ending length {length} early.")
                        stop_early = True
                        break
            except multiprocessing.TimeoutError:
                now = time.time()
                if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                    print(f"  ... [HEARTBEAT] {category_label} (L:{length}) running for {int((now-start_time)//60)}m")
                    last_heartbeat = now
            except StopIteration:
                break
    finally:
        pool.terminate()
        pool.join()
        log_result(f"Phase {category_label} (L:{length}) duration: {time.time()-start_time:.2f}s")

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(current_dir, OUTPUT_FILE), "w", encoding="utf-8") as f:
        f.write(f"--- ATTACK START: {time.ctime()} ---\n")

    targets = load_shadow_files(current_dir)

    run_dictionary_attack(targets, get_category1_candidates())

    charset_mix = string.ascii_letters + string.digits
    run_generic_brute_force(targets, 4, charset_mix, "Category 3")

    charset_low = string.ascii_lowercase
    run_generic_brute_force(targets, 6, charset_low, "Category 2")

if __name__ == "__main__":
    main()