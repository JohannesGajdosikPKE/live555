#include <stdio.h>

const char *contents = 
"#include \"winres.h\"\n"
"LANGUAGE LANG_GERMAN, SUBLANG_GERMAN_AUSTRIAN\n"
"VS_VERSION_INFO VERSIONINFO\n"
"  FILEVERSION %d,%d,%d,%d"
"  FILEFLAGSMASK 0x3fL\n"
"#ifdef _DEBUG\n"
"  FILEFLAGS 0x1L\n"
"#else\n"
"  FILEFLAGS 0x0L\n"
"#endif\n"
"  FILEOS 0x40004L\n"
"  FILETYPE 0x2L\n"
"  FILESUBTYPE 0x0L\n"
"BEGIN\n"
"    BLOCK \"StringFileInfo\"\n"
"    BEGIN\n"
"        BLOCK \"000004b0\"\n"
"        BEGIN\n"
//"            VALUE \"CompanyName\", \"PKE Holding AG\"\n"
//"            VALUE \"FileDescription\", \"streaming plugin\"\n"
"            VALUE \"InternalName\", \"RtspMStreamPlugin.dll\"\n"
"            VALUE \"LegalCopyright\", \"GNU LGPL, derived work by PKE Holding AG (C) from live555 by Live Networks, Inc, \"\n"
"            VALUE \"OriginalFilename\", \"RtspMStreamPlugin.dll\"\n"
"            VALUE \"ProductName\", \"RTSP MStream Plugin\"\n"
"            VALUE \"ProductVersion\", \"git %s\"\n"
"        END\n"
"    END\n"
"    BLOCK \"VarFileInfo\"\n"
"    BEGIN\n"
"        VALUE \"Translation\", 0x0, 1200\n"
"    END\n"
"END\n";

char buffer[16384];

#ifdef _WIN32
#define popen _popen
#endif

static const int plugin_version_digit_0 = 1;
static const int plugin_version_digit_1 = 4;
static const int plugin_version_digit_2 = 0;
static const int plugin_version_digit_3 = 18;


int main(int argc, char **argv) {
  char git_hash[256];
  {
    FILE *f = popen("git rev-parse HEAD","r");
    if (!f) {
      fprintf(stderr,"popen(\"git rev-parse HEAD\",\"r\") failed\n");
      return 1;
    }
    size_t size = fread(git_hash,1,sizeof(git_hash),f);
    if (size < 3) {
      fprintf(stderr,"no output from popen(\"git rev-parse HEAD\",\"r\")\n");
      return 1;
    }
    fclose(f);
    if (size == sizeof(git_hash)) size--;
    git_hash[size] = '\0';
    if (git_hash[size-1] == '\n') git_hash[size-1] = '\0';
  }
  FILE *f = fopen(argv[1],"w");
  fprintf(f,
          "const char *plugin_version=\"%d.%d.%d.%d\";\n"
          "const char *git_commit_hash=\"%s\";\n",
	  plugin_version_digit_0,
	  plugin_version_digit_1,
	  plugin_version_digit_2,
	  plugin_version_digit_3,
          git_hash);
  fclose(f);
  printf("Created file %s\n",argv[1]);

  if (argc > 2) {
    FILE *f = fopen(argv[2],"w");
    fprintf(f,contents,
            plugin_version_digit_0,
	    plugin_version_digit_1,
	    plugin_version_digit_2,
	    plugin_version_digit_3,
	    git_hash);
    fclose(f);
    printf("Created file %s\n",argv[2]);
  }
  return 0;
}
