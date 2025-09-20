/*
   american fuzzy lop - LLVM-mode wrapper for clang
   ------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This program is a drop-in replacement for clang, similar in most respects
   to ../afl-gcc. It tries to figure out compilation mode, adds a bunch
   of flags, and then calls the real compiler.
*/

#define AFL_MAIN


#include "alloc_inl.h"
#include "defs.h"
#include "debug.h"
#include "version.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  obj_path;               /* Path to runtime libraries         */
static u8** cc_params;              /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */
static u8* pwd;
static u8 is_cxx = 0;
static u8 clang_type = CLANG_TRACK_TYPE;
u8 need_lz = 0;


/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(u8* argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  slash = strrchr(argv0, '/');

  if (slash) {
    u8 *dir;
    
    
    char original_char = *slash;
    
    
    *slash = 0;
    dir = ck_strdup(argv0);
    
    
    *slash = original_char;
    
    tmp = alloc_printf("%s/pass/libcbi.so", dir);
    if (!access(tmp, R_OK)) {
      obj_path = dir;
      ck_free(tmp);
      return;
    }
    ck_free(tmp);
    ck_free(dir);
  }

  FATAL("Unable to find  'pass/libLoopHandlingPass.so'. Please set AFL_PATH");
}

static const char b64_tab[64] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
static u8* create_temp_dir(const char* target_name) {

  // Generate random directory name
  FILE* fd = fopen("/dev/urandom", "rb");
  if (fd == NULL)
    FATAL("Cannot open urandom");
  char dir_name[13];
  u8 tmp;
  for (size_t i = 0; i < sizeof(dir_name) - 1; ++i) {
    if (fread(&tmp, 1, 1, fd) != 1)
      FATAL("fread() failed");
    dir_name[i] = b64_tab[tmp % sizeof(b64_tab)];
  }
  dir_name[sizeof(dir_name) - 1] = 0;
  fclose(fd);

  // Create directories and files as init of dir
  const char* tmp_dir = getenv("WR_TMP_DIR");
  if (tmp_dir && tmp_dir[0] != '/')
    FATAL("Please use absolute path for WR_TMP_DIR");
  u8* ret = alloc_printf("%s/%s.%s",
    tmp_dir ? tmp_dir : "/tmp", target_name, dir_name);
  if (mkdir(ret, 0700) < 0) FATAL("mkdir() failed");
  return ret;
}

static void parse_out(const char* out, u8** dir, u8** name) {
  if (out == NULL)
    FATAL("No out file path");

  char* cp = strdup(out);

  u8* pos = strrchr(cp, '/');
  if (pos == NULL) {
    *name = cp;
    *dir = pwd;
  }
  else {
    *pos = 0;
    *name = pos + 1;
    if (out[0] == '/')
      *dir = alloc_printf("/%s", cp);
    else
      *dir = alloc_printf("%s/%s", pwd, cp);
  }
}

static u8 is_target(const u8* target_name, const u8* targets) {

  // "::" represent we want to treat everything as target
  if (strcmp(targets, "::") == 0)
    return 1;

  u8* iter = ck_strdup(targets);

  while (1) {

    u8* p = strchr(iter, ':');
    if (p == NULL)
      break;

    *p = 0;
    if (strcmp(target_name, iter) == 0)
      return 1;

    iter = p + 1;

  }

  return strcmp(target_name, iter) == 0;
}

static u8 check_if_assembler(u32 argc, const char **argv) {
  /* Check if a file with an assembler extension ("s" or "S") appears in argv */

  while (--argc) {
    u8 *cur = *(++argv);

    const u8 *ext = strrchr(cur, '.');
    if (ext && (!strcmp(ext + 1, "s") || !strcmp(ext + 1, "S"))) {
      return 1;
    }
  }

  return 0;
}


static void add_runtime() {
  if (clang_type != CLANG_FAST_TYPE)

    cc_params[cc_par_cnt++] = "-Wl,--whole-archive";
    cc_params[cc_par_cnt++] = alloc_printf("%s/lib/libdfsan_rt-x86_64.a", obj_path);
    cc_params[cc_par_cnt++] = "-Wl,--no-whole-archive";
    cc_params[cc_par_cnt++] =
        alloc_printf("-Wl,--dynamic-list=%s/lib/libdfsan_rt-x86_64.a.syms", obj_path);

    cc_params[cc_par_cnt++] = alloc_printf("%s/lib/libruntime.so", obj_path);
    cc_params[cc_par_cnt++] = alloc_printf("%s/lib/libDFSanIO.a", obj_path);
    if (need_lz != 0)
      cc_params[cc_par_cnt++] = alloc_printf("%s/lib/libZlibRt.a", obj_path);
    char *rule_obj = getenv(TAINT_CUSTOM_RULE_VAR);
    if (rule_obj) {
      cc_params[cc_par_cnt++] = rule_obj;
    }
  if (clang_type != CLANG_FAST_TYPE) {
    // cc_params[cc_par_cnt++] = "-pthread";
    if (!is_cxx)
      cc_params[cc_par_cnt++] = "-lstdc++";
    cc_params[cc_par_cnt++] = "-lrt";
  }
  
  cc_params[cc_par_cnt++] = "-Wl,--no-as-needed";
  cc_params[cc_par_cnt++] = "-Wl,--gc-sections"; // if darwin -Wl, -dead_strip
  cc_params[cc_par_cnt++] = "-ldl";
  cc_params[cc_par_cnt++] = "-lpthread";
  cc_params[cc_par_cnt++] = "-lm";
  if (need_lz != 0)
    cc_params[cc_par_cnt++] = "-lz";
}

static void add_dfsan_pass() {
  cc_params[cc_par_cnt++] = alloc_printf("-Wl,-mllvm=-load=%s/pass/libDFSanPass.so", obj_path);
  cc_params[cc_par_cnt++] =
      alloc_printf("-Wl,-mllvm=-chunk-dfsan-abilist=%s/rules/angora_abilist.txt", obj_path);
  cc_params[cc_par_cnt++] =
      alloc_printf("-Wl,-mllvm=-chunk-dfsan-abilist=%s/rules/dfsan_abilist.txt", obj_path);
  if (need_lz != 0 ) {
    cc_params[cc_par_cnt++] = 
        alloc_printf("-Wl,-mllvm=-chunk-dfsan-abilist=%s/rules/zlib_abilist.txt", obj_path);
  }
  
  char *rule_list = getenv(TAINT_RULE_LIST_VAR);
  if (rule_list) {
    cc_params[cc_par_cnt++] =
        alloc_printf("-Wl,-mllvm=-chunk-dfsan-abilist=%s", rule_list);
  }
}


/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {

  u8 fortify_set = 0, asan_set = 0, x_set = 0, maybe_linking = 1, bit_mode = 0;
  u8 maybe_assembler = 0;
  u8 *name;

  cc_params = ck_alloc((argc + 128) * sizeof(u8*));

  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;
  check_type(name);

  if (is_cxx) {
    cc_params[0] = (u8*)"clang++";
  } else {
    cc_params[0] = (u8*)"clang";
  }

  maybe_assembler = check_if_assembler(argc, argv);

  
  cc_params[cc_par_cnt++] = "-Qunused-arguments";

  /* Detect stray -v calls from ./configure scripts. */

  if (argc == 1 && !strcmp(argv[1], "-v")) maybe_linking = 0;

  u8 *target_path = NULL, *target_name = NULL;

  while (--argc) {
    u8* cur = *(++argv);

    if (!strcmp(cur, "-o")) parse_out(argv[1], &target_path, &target_name);

    if (!strcmp(cur, "-O1") || !strcmp(cur, "-O2") || !strcmp(cur, "-O3")) {
      continue;
    }

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
      maybe_linking = 0;

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-shared")) maybe_linking = 0;

    if (!strcmp(cur, "-Wl,-z,defs") ||
        !strcmp(cur, "-Wl,--no-undefined")) continue;

    cc_params[cc_par_cnt++] = cur;

  }

  if (target_path == NULL) {
    target_path = pwd;
    target_name = "a.out";
  }



  cc_params[cc_par_cnt++] = "-g";
  cc_params[cc_par_cnt++] = "-O0";
  cc_params[cc_par_cnt++] = "-flto"; 
  cc_params[cc_par_cnt++] = "-pie";
  cc_params[cc_par_cnt++] = "-fpic"; 
  cc_params[cc_par_cnt++] = "-fno-inline-functions"; 
  cc_params[cc_par_cnt++] = "-fno-discard-value-names"; 

  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  
  if (!asan_set) {

    if (getenv("AFL_USE_ASAN")) {

      if (getenv("AFL_USE_MSAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("ASAN and AFL_HARDEN are mutually exclusive");
      
      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=address";

    } else if (getenv("AFL_USE_MSAN")) {

      if (getenv("AFL_USE_ASAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("MSAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=memory";

    }

  }

#ifdef USE_TRACE_PC

  if (getenv("AFL_INST_RATIO"))
    FATAL("AFL_INST_RATIO not available at compile time with 'trace-pc'.");

#endif /* USE_TRACE_PC */

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-funroll-loops";

  }

  if (getenv("AFL_NO_BUILTIN")) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";

  }

  if (is_cxx) {
    if (clang_type == CLANG_FAST_TYPE) {
        cc_params[cc_par_cnt++] = alloc_printf("-L%s/lib/libcxx_fast/", obj_path);
        cc_params[cc_par_cnt++] = "-stdlib=libc++";
        cc_params[cc_par_cnt++] = "-Wl,--start-group";
        cc_params[cc_par_cnt++] = "-lc++abifast";
        cc_params[cc_par_cnt++] = "-lc++abi";
        cc_params[cc_par_cnt++] = "-Wl,--end-group";
    }
    else if (clang_type == CLANG_TRACK_TYPE) {
      cc_params[cc_par_cnt++] = alloc_printf("-L%s/lib/libcxx_track/", obj_path);
      cc_params[cc_par_cnt++] = "-stdlib=libc++";
      cc_params[cc_par_cnt++] = "-Wl,--start-group";
      cc_params[cc_par_cnt++] = "-lc++abitrack";
      cc_params[cc_par_cnt++] = "-lc++abi";
      cc_params[cc_par_cnt++] = "-Wl,--end-group";
    }
  }


  if (maybe_linking) {

    if (x_set) {
      cc_params[cc_par_cnt++] = "-x";
      cc_params[cc_par_cnt++] = "none";
    }

    add_runtime();
    
    const char* bb_targets = getenv("WR_BB_TARGETS");
    const char* targets = getenv("WR_TARGETS"); // "prog1:prog2" # or "::" for all programs
    u8 wr_inst = bb_targets != NULL && targets != NULL && \
      is_target(target_name, targets); 
    cc_params[cc_par_cnt++] = "--ld-path=ld.lld-10";
    if (wr_inst) {
      // If targets are set, we use WindRanger instrumentation.
      cc_params[cc_par_cnt++] = alloc_printf(
        "-Wl,-mllvm=-load=%s/pass/libcbi.so", obj_path);
      cc_params[cc_par_cnt++] = alloc_printf(
        "-Wl,-mllvm=-targets=%s", bb_targets);
      const u8* tmp = create_temp_dir(target_name);
      cc_params[cc_par_cnt++] = alloc_printf(
        "-Wl,-mllvm=-tmpdir=%s", tmp);
      add_dfsan_pass();
    }

    

  }

  cc_params[cc_par_cnt] = NULL;

}

void check_type(char *name) {
  u8 *use_fast = getenv("USE_FAST");
  u8 *use_dfsan = getenv("USE_DFSAN");
  u8 *use_track = getenv("USE_TRACK");
  u8 *use_pin = getenv("USE_PIN");
  if (use_fast) {
    clang_type = CLANG_FAST_TYPE;
  } else if (use_dfsan) {
    clang_type = CLANG_DFSAN_TYPE;
  } else if (use_track) {
    clang_type = CLANG_TRACK_TYPE;
  } else if (use_pin) {
    clang_type = CLANG_PIN_TYPE;
  }
  u8 *use_zlib = getenv("USE_ZLIB");
  printf("use_zlib: %s\n", use_zlib);
  if (use_zlib) {
    need_lz = 1;
  }
  if (!strcmp(name, "op-clang++")) {
    is_cxx = 1;
  }
}


/* Main entry point */

int main(int argc, char** argv) {


  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It serves as a drop-in replacement\n"
         "for clang, letting you recompile third-party code with the required runtime\n"
         "instrumentation. A common use pattern would be one of the following:\n\n"

         "  CC=%s/afl-clang-fast ./configure\n"
         "  CXX=%s/afl-clang-fast++ ./configure\n\n"

         "In contrast to the traditional afl-clang tool, this version is implemented as\n"
         "an LLVM pass and tends to offer improved performance with slow programs.\n\n"

         "You can specify custom next-stage toolchain via AFL_CC and AFL_CXX. Setting\n"
         "AFL_HARDEN enables hardening optimizations in the compiled code.\n\n", "1");

    exit(1);

  }

  pwd = getenv("PWD");
  if (pwd == NULL)
    FATAL("$PWD is not set");

  find_obj(argv[0]);

  edit_params(argc, argv);
  for (int i = 0; i < cc_par_cnt; i++) {
    printf("%s ", cc_params[i]);
  }
  printf("\n");

  execvp(cc_params[0], (char**)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}
