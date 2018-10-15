#ifndef EXT_OPTIONS_H
#define EXT_OPTIONS_H
#include "c.h"

#include <stdarg.h>
#include "assert.h"
#include "nodes/pg_list.h"
#include "plugstorage.h"
#define MAX_OPTION_LENGTH 8191
typedef enum {
  OPT_INT,  // the value of the option is int
  OPT_STR,  // the value of the option is string
  OPT_LTR,  // the option is a literal option with no value
  OPT_LST,  // the option has a list of value
  OPT_COL,  // the option is a name of a column
} T_Option;

typedef struct ext_option_data {
  char *option_name;  // name of option
  int name_len;       // length of the option name
  T_Option opt_type;  // type of the option
  bool need_opt;      // if this option is required
  int n_validvals;    // # of valid values
  char *strvalue;     // string value of the option
  char **validvals;   // array of valid values
} * ExtOptions;

static inline ExtOptions __attribute__((always_inline))
EXT_OPTIONS(T_Option type, char *option_name, bool need_opt, int n_validvals,
            ...) {
  ExtOptions opt = (ExtOptions)palloc0(sizeof(struct ext_option_data));
  opt->validvals = (char **)palloc0(sizeof(char *) * n_validvals);
  opt->option_name = option_name;
  opt->need_opt = need_opt;
  opt->opt_type = type;
  opt->name_len = strlen(option_name);
  opt->strvalue = NULL;
  opt->n_validvals = n_validvals;
  va_list arg_ptr;
  TupleDesc td;
  int i = 0;
  va_start(arg_ptr, n_validvals);
  if(type==OPT_COL) td = va_arg(arg_ptr, TupleDesc);
  do {
    if(type==OPT_COL)
      opt->validvals[i++] = td->attrs[i]->attname.data;
    else
      opt->validvals[i++] = va_arg(arg_ptr, char *);
  } while (i < n_validvals);
  va_end(arg_ptr);
  return opt;
}

#define EXT_OPTIONS_INIT(type, name, need_opt, n_validvals, ...) \
  struct ext_option_data t = {                                   \
    validvals : (char **)palloc0(sizeof(char *) * n_validvals),  \
    option_name : name,                                          \
    need_opt : need_opt,                                         \
    opt_type : type,                                             \
  }
#define CHECK_OPTIONS(format_opts, n_opts, opts, no_check_handler)            \
  do {                                                                        \
    int i;                                                                    \
    ListCell *opt;                                                            \
    foreach (opt, format_opts) {                                              \
      DefElem *defel = (DefElem *)lfirst(opt);                                \
      char *key = defel->defname;                                             \
      bool need_free_value = false, no_check;                                 \
      char *val = (char *)defGetString(defel, &need_free_value);              \
      /* check if the giving value is same as the defined ones*/              \
      for (no_check = true, i = 0; i < n_opts; i++)                           \
        if (strncasecmp(key, opts[i]->option_name, opts[i]->name_len) == 0) { \
          no_check = false;                                                   \
          if (opts[i]->opt_type == OPT_LST)                                   \
            val = (char *)NameListToQuotedString((List *)defel->arg);         \
          checkPlugStorageFormatOption(                                       \
              &(opts[i]->strvalue), key, val, opts[i]->need_opt,              \
              opts[i]->n_validvals, opts[i]->validvals);                      \
        }                                                                     \
      /* check if options are redundent*/                                     \
      if (no_check) no_check_handler(key);                                    \
      if (need_free_value) {                                                  \
        pfree(val);                                                           \
        val = NULL;                                                           \
      }                                                                       \
      AssertImply(need_free_value, NULL == val);                              \
    }                                                                         \
  } while (0)

#define EXPORT_OPTIONS(n_opts, opts, format_str)                             \
  do {                                                                       \
    int i, len, add_len;                                                     \
    for (i = 0, len = 0; i < n_opts; i++) {                                  \
      if (opts[i]->strvalue == NULL) continue;                               \
      add_len = 0;                                                           \
      switch (opts[i]->opt_type) {                                           \
        case OPT_LTR:                                                        \
          add_len += 3;                                                      \
          break;                                                             \
        case OPT_INT:                                                        \
        case OPT_STR:                                                        \
        case OPT_COL:                                                        \
          add_len += 2 + strlen(opts[i]->strvalue);                          \
          break;                                                             \
        case OPT_LST:                                                        \
          add_len += strlen(opts[i]->strvalue);                              \
          break;                                                             \
        default:                                                             \
          /*should never happen*/                                            \
          assert(false);                                                     \
      }                                                                      \
      add_len += 2 + opts[i]->name_len;                                      \
      if (len + add_len > FORMAT_OPTION_MAX_LEN) {                           \
        ereport(ERROR,                                                       \
                (errcode(ERRCODE_SYNTAX_ERROR),                              \
                 errmsg("format options must be less than %d bytes in size", \
                        FORMAT_OPTION_MAX_LEN),                              \
                 errOmitLocation(true)));                                    \
      }                                                                      \
      if (opts[i]->opt_type == OPT_LST)                                      \
        sprintf((char *)format_str + len, "%s %s ", opts[i]->option_name,    \
                opts[i]->strvalue);                                          \
      else if (opts[i]->opt_type == OPT_LTR)                                 \
        sprintf((char *)format_str + len, "%s '1' ", opts[i]->option_name);  \
      else                                                                   \
        sprintf((char *)format_str + len, "%s '%s' ", opts[i]->option_name,  \
                opts[i]->strvalue);                                          \
      len += add_len;                                                        \
    }                                                                        \
  } while (0)

static bool strcasemulticmp(char *, int, ...);
static void strmulticat(char **, int n, ...);

/* Accessors for pluggable storage format */
#define DECLARE_IUD_INTERFACES(name, op)      \
  PG_FUNCTION_INFO_V1(name##_##op##_init);    \
  PG_FUNCTION_INFO_V1(name##_##op);           \
  PG_FUNCTION_INFO_V1(name##_##op##_finish);  \
  Datum name##_##op##_init(PG_FUNCTION_ARGS); \
  Datum name##_##op(PG_FUNCTION_ARGS);        \
  Datum name##_##op##_finish(PG_FUNCTION_ARGS);

#define DECLARE_SCAN_INTERFACE(name)           \
  PG_FUNCTION_INFO_V1(name##_beginscan);       \
  PG_FUNCTION_INFO_V1(name##_getnext_init);    \
  PG_FUNCTION_INFO_V1(name##_getnext);         \
  PG_FUNCTION_INFO_V1(name##_rescan);          \
  PG_FUNCTION_INFO_V1(name##_endscan);         \
  PG_FUNCTION_INFO_V1(name##_stopscan);        \
  Datum name##_beginscan(PG_FUNCTION_ARGS);    \
  Datum name##_getnext_init(PG_FUNCTION_ARGS); \
  Datum name##_getnext(PG_FUNCTION_ARGS);      \
  Datum name##_rescan(PG_FUNCTION_ARGS);       \
  Datum name##_endscan(PG_FUNCTION_ARGS);      \
  Datum name##_stopscan(PG_FUNCTION_ARGS);

// Validators for pluggable storage format
#define DECLARE_VALIDATE_INTERFACES(name)                    \
  PG_FUNCTION_INFO_V1(name##_validate_interfaces);           \
  PG_FUNCTION_INFO_V1(name##_validate_options);              \
  PG_FUNCTION_INFO_V1(name##_validate_encodings);            \
  PG_FUNCTION_INFO_V1(name##_validate_datatypes);            \
  Datum name##_validate_interfaces(PG_FUNCTION_ARGS);        \
  Datum name##_validate_options(PG_FUNCTION_ARGS);           \
  Datum name##_validate_encodings(PG_FUNCTION_ARGS);         \
  Datum name##_validate_datatypes(PG_FUNCTION_ARGS);         \
  static void name##_option_check_value(const ExtOptions *); \
  static void name##_no_check_handler(const char *key);

#define BUILD_VALIDATE_INTERFACE(name)                                        \
  Datum name##_validate_interfaces(PG_FUNCTION_ARGS) {                        \
    PlugStorageValidator psv_interface =                                      \
        (PlugStorageValidator)(fcinfo->context);                              \
    if (pg_strncasecmp(psv_interface->format_name, #name, strlen(#name)) !=   \
        0) {                                                                  \
      ereport(                                                                \
          ERROR,                                                              \
          (errcode(ERRCODE_SYNTAX_ERROR),                                     \
           errmsg(#name "_validate_interface : incorrect format name \'%s\'", \
                  psv_interface->format_name)));                              \
    }                                                                         \
    PG_RETURN_VOID();                                                         \
  }

#define BUILD_NAME_FUNC(name)                                               \
  static FmgrInfo *get_##name##__func(char *function_name) {                \
    Assert(function_name);                                                  \
    Oid procOid = InvalidOid;                                               \
    FmgrInfo *procInfo = NULL;                                              \
    procOid = LookupPlugStorageValidatorFunc(#name, function_name);         \
    if (OidIsValid(procOid)) {                                              \
      procInfo = (FmgrInfo *)palloc(sizeof(FmgrInfo));                      \
      fmgr_info(procOid, procInfo);                                         \
    } else {                                                                \
      elog(ERROR, #name "_%s function was not found for pluggable storage", \
           function_name);                                                  \
    }                                                                       \
    return procInfo;                                                        \
  }

#define BUILD_GET_SCAN_FUNCTIONS(name)                                        \
  static void get_scan_functions(FileScanDesc file_scan_desc) {               \
    file_scan_desc->fs_ps_scan_funcs.beginscan =                              \
        get_##name##__func("beginscan");                                      \
    file_scan_desc->fs_ps_scan_funcs.getnext_init =                           \
        get_##name##__func("getnext_init");                                   \
    file_scan_desc->fs_ps_scan_funcs.getnext = get_##name##__func("getnext"); \
    file_scan_desc->fs_ps_scan_funcs.rescan = get_##name##__func("rescan");   \
    file_scan_desc->fs_ps_scan_funcs.endscan = get_##name##__func("endscan"); \
    file_scan_desc->fs_ps_scan_funcs.stopscan =                               \
        get_##name##__func("stopscan");                                       \
  }

#define BUILD_GET_IUD_FUNCTIONS(name, op, Type)                        \
  static void get_##op##_functions(Type ext_##op##_desc) {             \
    ext_##op##_desc->ext_ps_##op##_funcs.op##_init =                   \
        get_##name##__func(#op "_init");                               \
    ext_##op##_desc->ext_ps_##op##_funcs.op = get_##name##__func(#op); \
    ext_##op##_desc->ext_ps_##op##_funcs.op##_finish =                 \
        get_##name##__func(#op "_finish");                             \
  }

#define BUILD_VALIDATE_DATATYPES(name)                                        \
  /* void {$name}_validate_datatypes(TupleDesc tupDesc) */                    \
  Datum name##_validate_datatypes(PG_FUNCTION_ARGS) {                         \
    PlugStorageValidator psv = (PlugStorageValidator)(fcinfo->context);       \
    TupleDesc tup_desc = psv->tuple_desc;                                     \
                                                                              \
    for (int i = 0; i < tup_desc->natts; ++i) {                               \
      int32_t datatype =                                                      \
          (int32_t)(((Form_pg_attribute)(tup_desc->attrs[i]))->atttypid);     \
                                                                              \
      if (checkUnsupportedDataType(datatype)) {                               \
        ereport(                                                              \
            ERROR,                                                            \
            (errcode(ERRCODE_SYNTAX_ERROR),                                   \
             errmsg("unsupported data types %d for columns of external" #name \
                    "table is specified.Data types for columns of " #name     \
                    " external table must be "                                \
                    "SMALLINT, INT, BIGINT, REAL, FLOAT, DOUBLE PRECISION, "  \
                    "BOOL, DATE, TIME, TIMESTAMP, CHAR(n), VARCHAR(n), "      \
                    "TEXT or BYTEA.",                                         \
                    datatype),                                                \
             errOmitLocation(true)));                                         \
      }                                                                       \
    }                                                                         \
                                                                              \
    PG_RETURN_VOID();                                                         \
  }

#define BUILD_VALIDATE_ENCODINGS(name, n_encoding, ...)                 \
  /* void ${name}_validate_encodings(char *encodingName)*/              \
  Datum name##_validate_encodings(PG_FUNCTION_ARGS) {                   \
    PlugStorageValidator psv = (PlugStorageValidator)(fcinfo->context); \
    char *encoding_name = psv->encoding_name;                           \
    char buf[MAX_OPTION_LENGTH] = "", *ptr = buf;                       \
    strmulticat(ptr, n_encoding, __VA_ARGS__);                          \
    int i = 0;                                                          \
    if (strcasemulticmp(encoding_name, n_encoding, __VA_ARGS__)) {      \
      ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR),                    \
                      errmsg("\"%s\" is not a valid encoding for" #name \
                             " external table. Encoding for " #name     \
                             " external table must be %s.",             \
                             encoding_name, &ptr[1]),                   \
                      errOmitLocation(true)));                          \
    }                                                                   \
                                                                        \
    PG_RETURN_VOID();                                                   \
  }

/**  strmulticmp
 *   strmulticmp (char *s, int n, ...)；
 *   compare multiple strings, find the first not equal string
 *   and return the difference
 */
static inline bool __attribute__((always_inline))
strcasemulticmp(char *s, int n, ...) {
  va_list va;
  va_start(va, n);
  int i = 0, r = 0;
  char *tmp;
  do {
    tmp = va_arg(va, char *);
    r = strcasecmp(s, tmp);
    i++;
  } while (i < n && r == 0);
  va_end(va);
  return r;
}

/** strmulticat
 *           _._     _,-'""`-._
 *          (,-.`._,'(       |\`-/|
 *   strmulti   `-.-' \ )-`( , o o) (char* r, int n, ...)；
 *                    `-    \`_`"'-
 *   concat multiple strings together seperated by ',', and stores
 *   the result string in *r, *r should be allocated enough space;
 */
#define strmulticat(r, n, ...)                      \
  do {                                              \
    char *f = (char *)malloc(sizeof(char) * 3 * n); \
    for (int i = 0; i < n; i++) strcat(f, "%s,");   \
    f[3 * n - 1] = '\0';                            \
    sprintf(r, f, __VA_ARGS__);                     \
  } while (0)

#endif /* EXT_OPTIONS_H */