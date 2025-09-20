#include "regex.h"

#define MAX_STRING_LENGTH 1024
#define OVECCOUNT 30


int random_int(int min, int max) {
    if (min >= max) return min;
    return min + rand() % (max - min + 1);
}


char random_char_from_set(const char *charset) {
    if (!charset || *charset == '\0') return '\0';
    int len = strlen(charset);
    return charset[random_int(0, len - 1)];
}


char random_letter() {
    return random_int(0, 1) ? 
           random_int('A', 'Z') : 
           random_int('a', 'z');
}


char random_digit() {
    return random_int('0', '9');
}


char random_whitespace() {
    const char *whitespaces = " \t\n\r\f\v";
    return random_char_from_set(whitespaces);
}


void generate_from_atom(const char *pattern, int *pos, char *result, int *result_len) {
    if (*result_len >= MAX_STRING_LENGTH - 1) return;

    switch (pattern[*pos]) {
        case '.':  
            result[(*result_len)++] = random_int(32, 126);
            (*pos)++;
            break;
            
        case '\\':  
            (*pos)++;
            switch (pattern[*pos]) {
                case 'd':  
                    result[(*result_len)++] = random_digit();
                    break;
                case 'w':  
                    switch (random_int(0, 2)) {
                        case 0: result[(*result_len)++] = random_letter(); break;
                        case 1: result[(*result_len)++] = random_digit(); break;
                        case 2: result[(*result_len)++] = '_'; break;
                    }
                    break;
                case 's':  
                    result[(*result_len)++] = random_whitespace();
                    break;
                default:  
                    result[(*result_len)++] = pattern[*pos];
            }
            (*pos)++;
            break;
            
        case '[':  
            {
                (*pos)++;
                int start = *pos;
                while (pattern[*pos] != ']' && pattern[*pos] != '\0') {
                    (*pos)++;
                }
                if (pattern[*pos] == ']') {
                    int len = *pos - start;
                    char *charset = malloc(len + 1);
                    strncpy(charset, pattern + start, len);
                    charset[len] = '\0';
                    
                    
                    char expanded[256] = {0};
                    int exp_len = 0;
                    for (int i = 0; i < len; i++) {
                        if (charset[i] == '-' && i > 0 && i < len - 1) {
                            for (char c = charset[i-1] + 1; c < charset[i+1]; c++) {
                                if (exp_len < 255) {
                                    expanded[exp_len++] = c;
                                }
                            }
                        } else {
                            if (exp_len < 255) {
                                expanded[exp_len++] = charset[i];
                            }
                        }
                    }
                    expanded[exp_len] = '\0';
                    
                    result[(*result_len)++] = random_char_from_set(expanded);
                    free(charset);
                    (*pos)++;
                }
            }
            break;
            
        default:  
            result[(*result_len)++] = pattern[*pos];
            (*pos)++;
    }
}


static int parse_brace_quantifier(const char *pattern, int *pos, int *out_min, int *out_max) {
    if (pattern[*pos] != '{') return 0;
    int p = *pos + 1;
    int min = 0, max = 0;
    char num[16] = {0};
    int ni = 0;
    while (isdigit((unsigned char)pattern[p]) && ni < 15) num[ni++] = pattern[p++];
    if (ni == 0) return 0;
    num[ni] = '\0';
    min = max = atoi(num);
    if (pattern[p] == ',') {
        p++;
        ni = 0; memset(num, 0, sizeof(num));
        while (isdigit((unsigned char)pattern[p]) && ni < 15) num[ni++] = pattern[p++];
        if (ni == 0) {
            // {m,}
            max = min + 5;
        } else {
            num[ni] = '\0';
            max = atoi(num);
        }
    }
    if (pattern[p] != '}') return 0;
    p++;
    *pos = p;
    *out_min = min;
    *out_max = max;
    return 1;
}


void generate_random_string(const char *pattern, int *pos, char *result, int *result_len) {
    while (pattern[*pos] != '\0' && *result_len < MAX_STRING_LENGTH - 1) {
        
        if (pattern[*pos] == '^' || pattern[*pos] == '$') { (*pos)++; continue; }

        if (pattern[*pos] == ')') { 
            return;
        }

        if (pattern[*pos] == '(') {  
            (*pos)++;
            int group_pattern_start = *pos; 
            int first_result_len_before = *result_len;
            
            generate_random_string(pattern, pos, result, result_len);
            if (pattern[*pos] == ')') {
                (*pos)++;
                
                int repeats = 1; 
                if (pattern[*pos] == '*' || pattern[*pos] == '+' || pattern[*pos] == '?') {
                    char q = pattern[*pos];
                    (*pos)++;
                    if (q == '*') repeats = random_int(0, 5);
                    else if (q == '+') repeats = random_int(1, 6);
                    else repeats = random_int(0, 1);
                } else if (pattern[*pos] == '{') {
                    int qmin = 1, qmax = 1;
                    if (parse_brace_quantifier(pattern, pos, &qmin, &qmax)) {
                        repeats = random_int(qmin, qmax);
                    }
                }
                if (repeats == 0) {
                    
                    *result_len = first_result_len_before;
                } else if (repeats > 1) {
                    
                    for (int r = 1; r < repeats && *result_len < MAX_STRING_LENGTH - 1; r++) {
                        int tmp_pos = group_pattern_start;
                        int before = *result_len;
                        generate_random_string(pattern, &tmp_pos, result, result_len);
                        
                        if (pattern[tmp_pos] == ')') tmp_pos++;
                        
                        if (*result_len == before) break;
                    }
                }
            }
            continue;
        }

        if (pattern[*pos] == '|') { 
            (*pos)++;
            continue;
        }

        if (pattern[*pos] == '*' || pattern[*pos] == '+' || pattern[*pos] == '?' ) {
            
            (*pos)++;
            continue;
        }

        
        int atom_start_len = *result_len;
        int atom_pattern_start = *pos; 
        generate_from_atom(pattern, pos, result, result_len);

        
        if (pattern[*pos] == '*' || pattern[*pos] == '+' || pattern[*pos] == '?' || pattern[*pos] == '{') {
            int repeats = 1; 
            if (pattern[*pos] == '*') { (*pos)++; repeats = random_int(0, 5); }
            else if (pattern[*pos] == '+') { (*pos)++; repeats = random_int(1, 6); }
            else if (pattern[*pos] == '?') { (*pos)++; repeats = random_int(0, 1); }
            else if (pattern[*pos] == '{') {
                int qmin = 1, qmax = 1;
                if (parse_brace_quantifier(pattern, pos, &qmin, &qmax)) repeats = random_int(qmin, qmax);
            }
            if (repeats == 0) {
                *result_len = atom_start_len;
            } else if (repeats > 1) {
                
                for (int r = 1; r < repeats && *result_len < MAX_STRING_LENGTH - 1; r++) {
                    int tmp_pos = atom_pattern_start;
                    int before = *result_len;
                    generate_from_atom(pattern, &tmp_pos, result, result_len);
                    if (*result_len == before) break;
                }
            }
        }
    }
}


char* regex_generate(const char *regex) {
    static int seeded = 0;
    if (!seeded) { srand(time(NULL)); seeded = 1; }
    static char result[MAX_STRING_LENGTH];
    int pos = 0;
    int result_len = 0;
    memset(result, 0, sizeof(result));
    
    generate_random_string(regex, &pos, result, &result_len);
    result[result_len] = '\0';
    return result;
}

// int main() {

//     srand(time(NULL));
    

//     const char *patterns[] = {





//         NULL
//     };
    

//     for (int i = 0; patterns[i] != NULL; i++) {

//     }
    
//     return 0;
// }
