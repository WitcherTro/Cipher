#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/md5.h>
#include <omp.h>
#include <algorithm>
#include <set>
#include <cmath>
#include <cstring>

using namespace std;

struct Target {
    string filename;
    string login;
    string salt;
    unsigned char hash[16];
    bool cracked = false;
    string password;
    string category;
};

// Base64 decoding to binary hash
vector<unsigned char> base64_decode(const string& in) {
    static const string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[b64[i]] = i;
    vector<unsigned char> out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((unsigned char)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// Global logging to console and file
void log_cracked(Target& t, string pass, string cat) {
    t.cracked = true;
    t.password = pass;
    t.category = cat;
    string msg = "  [+] CRACKED: " + t.filename + " | " + t.login + " | " + pass + " (" + cat + ")";
    cout << msg << endl;
    ofstream out("results.txt", ios::app);
    out << msg << endl;
}

// --- Category 1: Dictionary Attack (Full Scan) ---
void run_category1_full(vector<Target>& targets) {
    cout << "[Category 1] Starting full Dictionary Attack on all hashes..." << endl;

    vector<string> base_names = {
        "alexander", "alexandra", "adam", "adela", "adrian", "adriana", "alica", "alena", "andrea", "andrej",
        "anna", "anton", "barbora", "beata", "benjamin", "bozena", "branislav", "branko", "cyril", "daniela",
        "daniel", "darina", "david", "denisa", "dominika", "dominik", "dusan", "edita", "eduard", "elena",
        "emil", "emilia", "erik", "erika", "eva", "filip", "frantisek", "gabriel", "gabriela", "hana",
        "helena", "henrich", "ivan", "ivana", "iveta", "jakub", "jan", "janka", "jarmila", "jaroslav",
        "jozef", "julia", "julius", "juraj", "kamil", "karol", "katarina", "klara", "klaudia", "kristina",
        "ladislav", "laura", "lenka", "lucia", "ludmila", "lukas", "magdalena", "marek", "marian", "maria",
        "marta", "martin", "martina", "matej", "matus", "michal", "michaela", "milan", "milos", "miroslav",
        "monika", "natalia", "nikola", "nina", "olga", "oliver", "ondrej", "oskar", "patrik", "patricia",
        "pavol", "petra", "peter", "radovan", "radoslav", "rastislav", "renata", "richard", "robert",
        "roman", "samuel", "silvia", "simona", "simon", "stanislav", "stefan", "tamara", "tatiana",
        "terezia", "tibor", "timotej", "tomas", "veronika", "viera", "viktoria", "viktor", "viliam", "vladimir",
        "zdeno", "zora", "zuzana", "misko", "ferko", "janko", "katka", "zuzka", "evka", "lucka", "petko",
        "samko", "matko", "jozko", "matusko", "kubko"
    };

    vector<string> suffixes = {"ka", "ko", "icka", "ik", "uska", "ulo", "inka"};
    set<string> temp_dict;

    for (string name : base_names) {
        temp_dict.insert(name);
        string stem3 = name.substr(0, min((int)name.length(), 3));
        string stem4 = name.substr(0, min((int)name.length(), 4));
        for (string sfx : suffixes) {
            temp_dict.insert(stem3 + sfx);
            temp_dict.insert(stem4 + sfx);
        }
    }

    vector<string> dictionary;
    for (string word : temp_dict) {
        dictionary.push_back(word);
        for (int i = 0; i < (int)word.length(); i++) {
            string variant = word;
            variant[i] = toupper(variant[i]);
            dictionary.push_back(variant);
        }
    }

    double start = omp_get_wtime();
    int found_count = 0;

    #pragma omp parallel for schedule(dynamic) reduction(+:found_count)
    for (int i = 0; i < (int)targets.size(); i++) {
        for (const string& cand : dictionary) {
            MD5_CTX ctx;
            unsigned char digest[16];
            MD5_Init(&ctx);
            MD5_Update(&ctx, cand.c_str(), cand.length());
            MD5_Update(&ctx, targets[i].salt.c_str(), targets[i].salt.length());
            MD5_Final(digest, &ctx);

            if (memcmp(digest, targets[i].hash, 16) == 0) {
                #pragma omp critical
                {
                    if (!targets[i].cracked) {
                        log_cracked(targets[i], cand, "Category 1");
                        found_count++;
                    }
                }
                break;
            }
        }
    }
    double duration = omp_get_wtime() - start;
    string end_msg = "[Category 1] Found: " + to_string(found_count) + " passwords. Time: " + to_string(duration) + " s.";
    cout << end_msg << endl;
    ofstream out("results.txt", ios::app);
    out << end_msg << endl;
}

// --- Brute Force (Category 2 & 3) ---
void run_brute_force(vector<Target>& targets, int length, const string& charset, int cat_num) {
    set<string> files_needed = {"shadow1.txt", "shadow2.txt", "shadow3.txt", "shadow4.txt"};
    set<string> satisfied_files;
    for (auto& t : targets) {
        if (t.cracked && (t.category == "Category " + to_string(cat_num))) satisfied_files.insert(t.filename);
    }

    if (satisfied_files.size() >= 4) {
        cout << "[Category " << cat_num << "] Objective met, skipping length " << length << endl;
        return;
    }

    long long total = (long long)pow(charset.length(), length);
    cout << "[Category " << cat_num << "] L:" << length << " | " << total << " combinations..." << endl;

    bool stop_early = false;
    double start_time = omp_get_wtime();

    #pragma omp parallel
    {
        MD5_CTX ctx_base;
        #pragma omp for schedule(dynamic, 2000)
        for (long long i = 0; i < total; i++) {
            if (stop_early) continue;

            char pass[12];
            long long temp = i;
            for (int l = 0; l < length; l++) {
                pass[l] = charset[temp % charset.length()];
                temp /= charset.length();
            }
            pass[length] = '\0';

            for (int j = 0; j < (int)targets.size(); j++) {
                if (targets[j].cracked) continue;

                unsigned char digest[16];
                MD5_Init(&ctx_base);
                MD5_Update(&ctx_base, pass, length);
                MD5_Update(&ctx_base, targets[j].salt.c_str(), targets[j].salt.length());
                MD5_Final(digest, &ctx_base);

                if (memcmp(digest, targets[j].hash, 16) == 0) {
                    #pragma omp critical
                    {
                        if (!targets[j].cracked) {
                            log_cracked(targets[j], pass, "Category " + to_string(cat_num));
                            satisfied_files.insert(targets[j].filename);
                            if (satisfied_files.size() >= 4) stop_early = true;
                        }
                    }
                }
            }
        }
    }
    double duration = omp_get_wtime() - start_time;
    string time_msg = "  Phase [Category " + to_string(cat_num) + " L:" + to_string(length) + "] took: " + to_string(duration) + " s.";
    cout << time_msg << endl;
    ofstream out("results.txt", ios::app);
    out << time_msg << endl;
}

int main() {
    ofstream out("results.txt");
    out << "--- ATTACK STARTED: " << omp_get_wtime() << " ---" << endl;
    out.close();

    vector<Target> targets;
    vector<string> files = {"shadow1.txt", "shadow2.txt", "shadow3.txt", "shadow4.txt"};
    for (string fname : files) {
        ifstream f(fname);
        string line;
        while (getline(f, line)) {
            stringstream ss(line);
            string u, s, h;
            if (getline(ss, u, ':') && getline(ss, s, ':') && getline(ss, h, ':')) {
                Target t; t.filename = fname; t.login = u; t.salt = s;
                vector<unsigned char> dec = base64_decode(h);
                if (dec.size() == 16) { memcpy(t.hash, dec.data(), 16); targets.push_back(t); }
            }
        }
    }

    if (targets.empty()) return 1;
    cout << "Loaded " << targets.size() << " hashes." << endl;

    // 1. Dictionary Attack
    run_category1_full(targets);

    // 2. Mixed Alphanumeric (Category 3)
    string charset_mix = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    run_brute_force(targets, 4, charset_mix, 3);

    // 3. Lowercase (Category 2)
    string charset_low = "abcdefghijklmnopqrstuvwxyz";
    run_brute_force(targets, 6, charset_low, 2);

    cout << "\n--- FINISHED. Check results.txt ---" << endl;
    return 0;
}